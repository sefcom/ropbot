import claripy


class NameAnnotation(claripy.Annotation):
    def __init__(self, name: str):
        self.name = name

    @property
    def eliminatable(self):
        return False

    @property
    def relocatable(self):
        return True

    def __repr__(self):
        return f"<{self.__class__.__name__}: {self.name}>"

    def __hash__(self):
        return hash((self.__class__.__name__, self.name))

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.name == other.name


REGS = {
    "riscv": (
        "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
        "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11",
        "t0", "t1", "t2", "t3", "t4", "t5", "t6",
        "ra", "gp", "tp",
    ),
    "aarch64": ("fp", "lr")
               # + tuple(f"w{i}" for i in range(28 + 1))
               + tuple(f"x{i}" for i in range(28 + 1))
    ,
}
