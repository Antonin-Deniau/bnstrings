from binaryninja import *
import r2pipe

def spawn(bv):
	class Task(BackgroundTaskThread):
		def run(self):
			r2 = r2pipe.open(bv.file.filename.replace(".bndb", ""))

			r2.cmd("aaaa")
			strings = r2.cmdj("izzj~{{string}}")
			r2.quit()

			for string in strings:
				typ = bv.parse_type_string("char[{}]".format(string["size"]))[0]
				addr = int(string["paddr"])
				bv.define_user_data_var(addr, typ)

			log_info("{} string(s) loaded".format(len(strings)))

	task = Task()
	task.start()

PluginCommand.register("Find strings", "Find strings with radare2", spawn)
