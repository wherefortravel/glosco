extends Node2D

@export var texture: Texture2D = preload("res://assets/default/host.svg"):
	set(value):
		texture = value
		queue_redraw()

@export var display_name: String = "(unknown)":
	set(value):
		display_name = value
		queue_redraw()
		
@onready var display_font: Font = ThemeDB.fallback_font

signal position_changed

var dragging = false

func _unhandled_input(event):
	var ev = make_input_local(event)
	var size = texture.get_size()
	var rect = Rect2(size / -2, size)
	if ev is InputEventMouseButton:
		if ev.pressed and rect.has_point(ev.position):
			dragging = true
			get_viewport().set_input_as_handled()
		elif dragging and not ev.pressed:
			dragging = false
	elif ev is InputEventMouseMotion and dragging:
		position += ev.position
		self.position_changed.emit()
		
func _draw():
	var size = texture.get_size()
	draw_texture(texture, size / -2, modulate * self_modulate)
	draw_string(display_font, Vector2(0, size.y / 2), display_name,
		HORIZONTAL_ALIGNMENT_CENTER,
	)
