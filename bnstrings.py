from binaryninja import *
from binaryninja.enums import SymbolType
import r2pipe, base64

def spawn(bv):
	class Task(BackgroundTaskThread):
		def run(self):
			r2 = r2pipe.open(bv.file.filename.replace(".bndb", ""))

			loaded = 0
			r2.cmd("aaaa")
			stri = r2.cmdj("izj")
			r2.quit()

			for string in stri:
				addr = int(string["vaddr"])
				name = base64.b64decode(string["string"])
				size = string["size"]

				symbol = Symbol(SymbolType.DataSymbol, addr, name)
				bv.define_user_symbol(symbol)

				t = bv.parse_type_string("char[{}]".format(size))
				bv.define_user_data_var(addr, t[0])
				loaded += 1
	
			log_info("{} string(s) loaded".format(loaded))

	task = Task()
	task.start()

PluginCommand.register("Find strings", "Find strings with radare2", spawn)
