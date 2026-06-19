import ghidra.app.decompiler.DecompInterface as DecompInterface
import ghidra.program.model.listing.Function as Function
import json, os

def listing_funcs(p):
    fm = p.getFunctionManager()
    out = []
    for f in fm.getFunctions(True):
        entry = f.getEntryPoint().getOffset()
        size = f.getBody().getNumAddresses()
        name = f.getName()
        refs = []
        try:
            for r in f.getReferences():
                pass
        except Exception:
            pass
        out.append({"rva": "0x%x" % entry, "size": size, "name": name})
    return out

def listing_strings(p):
    out = []
    ds = p.getListing().getDataIterator()
    count = 0
    while ds.hasNext() and count < 5000:
        d = ds.next()
        try:
            v = d.getValue()
            if v is not None:
                s = str(v)
                if len(s) > 3 and len(s) < 256:
                    addr = d.getAddress().getOffset()
                    out.append({"rva": "0x%x" % addr, "value": s})
                    count += 1
        except Exception:
            pass
    return out

def main():
    p = currentProgram
    out_path = os.environ.get("RVA_OUT", "/tmp/rvas.json")
    funcs = listing_funcs(p)
    strings = listing_strings(p)
    result = {
        "program": p.getName(),
        "image_base": "0x%x" % p.getImageBase().getOffset(),
        "functions_count": len(funcs),
        "functions": funcs,
        "strings_count": len(strings),
        "strings": strings,
    }
    with open(out_path, "w") as f:
        json.dump(result, f, indent=2)
    print("WROTE %s  funcs=%d  strings=%d" % (out_path, len(funcs), len(strings)))

main()
