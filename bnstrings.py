from binaryninja import *
import r2pipe

def spawn(bv):
  r2 = r2pipe.open(bv.file.filename.replace(".bndb", ""))

  r2.cmd("aaaa")
  strings = r2.cmdj("izzj")
  r2.quit()

  log_info("{} string(s) loaded".format(len(strings)))

  for string in strings:
    typ = bv.parse_type_string("char[{}]".format(string["size"]))[0]
    addr = int(string["paddr"])
    bv.define_user_data_var(addr, typ)

PluginCommand.register("Find strings", "Find strings with radare2", spawn)
