# Copyright (c) 2012, Vasilis Pappas <vpappas@cs.columbia.edu>
# This file is part of Orp http://nsl.cs.columbia.edu/projects/orp

# Additionally modified by Mahmood Sharif <mahmoods@alumni.cmu.edu>
# Alternate contact is Keane Lucas <keanelucas@cmu.edu>

class BasicBlock:

  NORMAL = 0
  ENTRY  = 1
  EXIT   = 2

  def __init__(self, begin, end, code):
    self.begin = begin
    self.end = end
#    self.instrs = [i for a, i in list(code.items()) if a >= begin and a <= end]
    self.instrs = [i for a, i in code.items() if begin <= a <= end]  # ✅ 불필요한 list 변환 제거

    #self.instrs.sort(key=lambda x: x.addr)
    if self.instrs:
        self.instrs.sort(key=lambda x: getattr(x, "addr", 0))  # ✅ addr이 없으면 기본값 0 사용

    self.successors = []
    self.type = BasicBlock.NORMAL
    #if len(self.instrs) == 0: #it's always 0 now .. FIXME
    if not self.instrs:  # ✅ 리스트가 비어있으면 바로 return
        return
    if self.instrs[0].f_entry:
      self.type |= BasicBlock.ENTRY
    if self.instrs[-1].f_exit:
      self.type |= BasicBlock.EXIT

  def reschedule(self):
    pass

  def __repr__(self):
    return "0x%08X : 0x%08X" % (self.begin, self.end)

