import flare_emu
import idb
import re

class PythonIDBAnalysisHelper(flare_emu.AnalysisHelper):
    def __init__(self, sample):
        super(PythonIDBAnalysisHelper, self).__init__()
        #self.fp = fp
        with open(sample, 'rb') as f:
            buffer = f.read()
        db = idb.from_buffer(buffer)
        api = idb.IDAPython(db)
        self.idautils = api.idautils
        self.idaapi = api.idaapi
        self.idc = api.idc

        info = self.idaapi.get_inf_structure()
        if info.procname == "metapc":
            self.arch = "X86"
        else:
            self.arch = info.procname
        if info.is_64bit():
            self.bitness = 64
        elif info.is_32bit():    
            self.bitness = 32
        else:
            self.bitness = None
        if info.filetype == 11:
            self.filetype = "PE"
        elif info.filetype == 25:
            self.filetype = "MACHO"
        elif info.filetype == 18:
            self.filetype = "ELF"
        else:
            self.filetype = "UNKNOWN"

    def getFuncStart(self, addr):
        ret = self.idc.get_func_attr(addr, self.idc.FUNCATTR_START)
        if ret == self.idc.BADADDR:
            return None
        return ret

    def getFuncEnd(self, addr):
        ret =  self.idc.get_func_attr(addr, self.idc.FUNCATTR_END)
        if ret == self.idc.BADADDR:
            return None
        return ret

    def getFuncName(self, addr, normalized=True):
        if normalized:
            return self.normalizeFuncName(self.idc.get_func_name(addr))
        else:
            return self.idc.get_func_name(addr)

    def getMnem(self, addr):
        return self.idc.print_insn_mnem(addr)

    def _getBlockByAddr(self, addr, flowchart):
        for bb in flowchart:
            if (addr >= bb.start_ea and addr < bb.end_ea) or addr == bb.start_ea:
                return bb
        return None

    # gets address of last instruction in the basic block containing addr
    def getBlockEndInsnAddr(self, addr, flowchart):
        bb = self._getBlockByAddr(addr, flowchart)
        return self.idc.prev_head(bb.end_ea, self.idc.get_inf_attr(self.idc.INF_MIN_EA))

    def skipJumpTable(self, addr):
        pass

    def getMinimumAddr(self):
        return self.idc.get_inf_attr(self.idc.INF_MIN_EA)

    def getMaximumAddr(self):
        return self.idc.get_inf_attr(self.idc.INF_MAX_EA)

    def getBytes(self, addr, size):
        return self.idc.get_bytes(addr, size, False)

    def getCString(self, addr):
        buf = ""
        while self.getBytes(addr, 1) != "\x00" and self.getBytes(addr, 1) is not None:
            buf += self.getBytes(addr, 1)
            addr += 1

        return buf

    def getOperand(self, addr, opndNum):
        return self.idc.print_operand(addr, opndNum)

    def getWordValue(self, addr):
        return self.idc.get_wide_word(addr)

    def getDwordValue(self, addr):
        return self.idc.get_wide_dword(addr)

    def getQWordValue(self, addr):
        return self.idc.get_qword(addr)

    def isThumbMode(self, addr):
        return self.idc.get_sreg(addr, "T") == 1

    def getSegmentName(self, addr):
        return self.idc.get_segm_name(addr)

    def getSegmentStart(self, addr):
        return self.idc.get_segm_start(addr)

    def getSegmentEnd(self, addr):
        return self.idc.get_segm_end(addr)

    def getSegmentDefinedSize(self, addr):
        size = 0
        segEnd = self.getSegmentEnd(addr)
        addr = self.getSegmentStart(addr)
        while self.idc.has_value(self.idc.get_full_flags(addr)):
            if addr >= segEnd:
                break
            size += 1
            addr += 1
        return size

    def getSegments(self):
        return self.idautils.Segments()
        
    def getSegmentSize(self, addr):
        return self.getSegmentEnd(addr) - self.getSegmentStart(addr)
        
    def getSectionName(self, addr):
        return self.getSegmentName(addr)

    def getSectionStart(self, addr):
        return self.getSegmentStart(addr)

    def getSectionEnd(self, addr):
        return self.getSegmentEnd(addr)

    def getSectionSize(self, addr):
        return self.getSegmentSize(addr)

    def getSections(self):
        return self.getSegments()

    # gets disassembled instruction with names and comments as a string
    def getDisasmLine(self, addr):
        return self.idc.generate_disasm_line(addr, 0)

    def getName(self, addr):
        return self.idc.get_name(addr, self.idc.ida_name.GN_VISIBLE)

    def getNameAddr(self, name):
        name = self.idc.get_name_ea_simple(name)
        if name == "":
            name = self.idc.get_name_ea_simple(self.normalizeFuncName(name))
        return name

    def getOpndType(self, addr, opndNum):
        return self.idc.get_operand_type(addr, opndNum)

    def getOpndValue(self, addr, opndNum):
        return self.idc.get_operand_value(addr, opndNum)

    def makeInsn(self, addr):
        if self.idc.create_insn(addr) == 0:
            self.idc.del_items(addr, self.idc.DELIT_EXPAND)
            self.idc.create_insn(addr)
        self.idc.auto_wait()

    def createFunction(self, addr):
        pass

    def getFlowChart(self, addr):
        function = self.idaapi.get_func(addr)
        return list(self.idaapi.FlowChart(function))


    def getSpDelta(self, addr):
        f = self.idaapi.get_func(addr)
        return self.idaapi.get_sp_delta(f, addr)

    def getXrefsTo(self, addr):
        return list(map(lambda x: x.frm, list(self.idautils.XrefsTo(addr))))

    def getArch(self):
        return self.arch

    def getBitness(self):
        return self.bitness

    def getFileType(self):
        return self.filetype

    def getInsnSize(self, addr):
        return self.idc.get_item_size(addr)

    def isTerminatingBB(self, bb):
        if (bb.type == self.idaapi.fcb_ret or bb.type == self.idaapi.fcb_noret or
                (bb.type == self.idaapi.fcb_indjump and len(list(bb.succs())) == 0)):
            return True
        for b in bb.succs():
            if b.type == self.idaapi.fcb_extern:
                return True

        return False
        
    def skipJumpTable(self, addr):
        while self.idc.print_insn_mnem(addr) == "":
            addr = self.idc.next_head(addr, self.idc.get_inf_attr(self.idc.INF_MAX_EA))
        return addr

    def setName(self, addr, name, size=0):
        self.idc.set_name(addr, name, self.idc.SN_NOCHECK)
    
    def setComment(self, addr, comment, repeatable=False):
        self.idc.set_cmt(addr, comment, repeatable)
        
    def normalizeFuncName(self, funcName):
        # remove appended _n from IDA Pro names
        funcName = re.sub(r"_[\d]+$", "", funcName)
        return funcName
