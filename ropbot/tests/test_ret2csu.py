import angr
import angrop  # noqa: F401


def test_ret2csu_payload_layout():
    project = angr.Project("/bin/true", auto_load_libs=False)
    rop = project.analyses.ROP()
    chain = rop.ret2csu(0x401000, 0x402000, 0x403000, 1,
                        [3, 0x404000, 8], next_pc=0x405000)
    words = [int.from_bytes(chain.payload_str()[i:i + 8], "little")
             for i in range(0, len(chain.payload_str()), 8)]
    assert words[:8] == [0x401000, 1, 2, 3, 0x404000, 8, 0x403000, 0x402000]
    assert words[-1] == 0x405000
