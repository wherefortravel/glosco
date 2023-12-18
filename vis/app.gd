extends Control

func _ready():
	OS.low_processor_usage_mode = true
	%Graph.path = "/home/grissess/Projects/glosco/target/debug/glosco.db"


func _on_refresh_intv_value_changed(value):
	%Graph.update_period = value
	%Graph.queue_redraw()


func _on_hist_value_changed(value):
	%Graph.history = value
	%Graph.queue_redraw()


func _on_idents_reload_pressed():
	%Idents.clear()
	for ident in %Graph.get_idents():
		%Idents.add_item(ident)


func _on_idents_multi_selected(index, selected):
	%Graph.interest_list = Array(%Idents.get_selected_items()).map(
		func(idx): return %Idents.get_item_text(idx)
	)
