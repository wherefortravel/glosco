extends Node2D

# Order is important: we prefer drawing later states to former states when all are available
enum DrawState {NONE, CLESS, ENDED, RESET, FAILED, ACTIVE}

var query: Array[Dictionary] = []
var hosts: Dictionary = {}
var db: SQLite = null
var path: String = "":
	set(value):
		path = value
		try_open_db()
		
var theme: Theme = null:
	get:
		if theme:
			return theme
		theme = load(ProjectSettings["gui/theme/custom"])
		return theme
		
@export var interest_list: Array:
	set(value):
		interest_list = value
		update_interest()

@export var host_class: PackedScene = preload("res://host.tscn")
@export var history: float = 5.0
@export var update_period: int = 250

@onready var next_update: int = Time.get_ticks_msec()

const SPACE = Vector2(0, 12)

func get_host(ip):
	if ip not in hosts:
		var host = host_class.instantiate()
		host.name = ip
		host.display_name = ip
		host.position = Vector2(randf(), randf()) * get_viewport_rect().size
		host.position_changed.connect(queue_redraw)
		add_child(host)
		hosts[ip] = host
	return hosts[ip]
	
func get_idents() -> Array:
	if not db:
		return []
	db.query("SELECT DISTINCT ident FROM state ORDER BY ident;")
	var res = db.query_result.map(func(row): return row["ident"])
	return res

func try_open_db():
	if not FileAccess.file_exists(path):
		db = null
		return
	db = SQLite.new()
	db.path = path
	#db.verbosity_level = db.QUIET  # squelch "locked" error races
	if not db.open_db():
		db = null
		return
	db.query("PRAGMA journal_mode=WAL;")
	update_interest()
	
func update_interest():
	if not db:
		return
	db.query("CREATE TABLE IF NOT EXISTS ident_interest (ident); DELETE FROM ident_interest;")
	db.insert_rows("ident_interest", interest_list.map(func(nm): return {"ident": nm}))
	
func do_query() -> bool:
	if not interest_list.is_empty():
		return db.query("SELECT * FROM latest_ins WHERE ident IN (SELECT * FROM ident_interest);")
	return db.query("SELECT * FROM latest_ins;")
	#return db.query_with_bindings("SELECT * FROM state WHERE instime > ?;", [Time.get_unix_time_from_system() - history])

func _process(delta):
	var now = Time.get_ticks_msec()
	if (not db) or next_update > now:
		return
		
	if do_query():
		next_update = now + update_period
		query = db.query_result
		print("rows this update: ", len(query))
		var qend = Time.get_ticks_msec()
		print("query time: ", qend - now)
		queue_redraw()
		
func is_ephemeral_port(p: int) -> bool:
	return p >= 32768 && p < 61000
	
func _draw():
	var unix_now = Time.get_unix_time_from_system()
	var pmap = {}
	
	for row in query:

		var ds = DrawState.ACTIVE
		var recent = 0
		if row["pkind"]:
			if row["instime"] > recent:
				recent = row["instime"]
			ds = DrawState.FAILED
		elif row["close"]:
			if row["instime"] > recent:
				recent = row["instime"]
			match row["close"]:
				Global.Closed.CONNECTIONLESS:
					ds = DrawState.CLESS
				Global.Closed.RESET:
					ds = DrawState.RESET
				Global.Closed.NORMAL, Global.Closed.TIMEOUT:
					ds = DrawState.ENDED

		var color: Color
		match ds:
			DrawState.NONE:
				continue
			DrawState.CLESS:
				color = theme.get_color("conn_cless", "Graph")
			DrawState.ENDED:
				color = theme.get_color("conn_ended", "Graph")
			DrawState.RESET:
				color = theme.get_color("conn_reset", "Graph")
			DrawState.FAILED:
				color = theme.get_color("conn_failed", "Graph")
			DrawState.ACTIVE:
				color = theme.get_color("conn_active", "Graph")
		if ds != DrawState.NONE and ds != DrawState.ACTIVE:
			var fade = (unix_now - recent) / history
			var is_ephem = [row["srcport"], row["dstport"]].any(is_ephemeral_port)
			if fade > 1 and is_ephem:
				continue
			color.a = 1.0 - clampf(fade, 0.0, 0.9)
			
		var hsrc = get_host(row['srchost'])
		var hdst = get_host(row['dsthost'])
		if hsrc not in pmap:
			pmap[hsrc] = hsrc.position
		if hdst not in pmap:
			pmap[hdst] = hdst.position
		var hsp = pmap[hsrc]
		var hdp = pmap[hdst]
		pmap[hsrc] += SPACE
		pmap[hdst] += SPACE
		
		draw_line(
			hsp, hdp,
			color,
		)
		draw_string(hsrc.display_font, hsp, str(row["srcport"]), HORIZONTAL_ALIGNMENT_LEFT, -1, 16, color)
		draw_string(hdst.display_font, hdp, str(row["dstport"]), HORIZONTAL_ALIGNMENT_LEFT, -1, 16, color)
