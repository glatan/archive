use super::*;

// ============================================================
// MS-CFB ([MS-CFB] v20210625) integration tests
// ============================================================

#[test]
fn test_mscfb_roundtrip_via_python_reference() {
    use std::process::{Command, Stdio};

    // Independent reference: a minimal v3 CFB writer written against
    // [MS-CFB] §2 directly (not derived from the crate's builder).
    // Layout: sector 0 = FAT, 1 = directory, 2 = mini FAT,
    // 3 = mini stream, 4.. = regular stream data.
    let script = concat!(
        "import sys, struct\n",
        "SS=512; EOC=0xFFFFFFFE; FREE=0xFFFFFFFF; FATS=0xFFFFFFFD; NOS=0xFFFFFFFF\n",
        "def dirent(name,typ,left,right,child,start,size):\n",
        "    e=bytearray(128)\n",
        "    n=name.encode('utf-16-le')+b'\\x00\\x00'\n",
        "    e[:len(n)]=n\n",
        "    struct.pack_into('<H',e,64,len(n))\n",
        "    e[66]=typ; e[67]=1\n",
        "    struct.pack_into('<I',e,68,left)\n",
        "    struct.pack_into('<I',e,72,right)\n",
        "    struct.pack_into('<I',e,76,child)\n",
        "    struct.pack_into('<I',e,116,start)\n",
        "    struct.pack_into('<Q',e,120,size)\n",
        "    return bytes(e)\n",
        "big=bytes((i%251) for i in range(5000)).ljust(5120,b'\\x00')\n",
        "small=b'reference mini stream contents'\n",
        "fat=[FATS,EOC,EOC,EOC]+[FREE]*124\n",
        "for i in range(4,13): fat[i]=i+1\n",
        "fat[13]=EOC\n",
        "mfat=[EOC]+[FREE]*127\n",
        "mdir=dir=dirent('Root Entry',5,NOS,NOS,1,3,64)\n",
        "mdir+=dirent('Storage 1',1,NOS,NOS,2,0,0)\n",
        "mdir+=dirent('Stream Small',2,NOS,3,NOS,0,len(small))\n",
        "mdir+=dirent('Stream Big',2,NOS,NOS,NOS,4,5000)\n",
        "ms=bytearray(SS); ms[:len(small)]=small\n",
        "f=bytearray(SS+14*SS)\n",
        "f[0:8]=bytes([0xD0,0xCF,0x11,0xE0,0xA1,0xB1,0x1A,0xE1])\n",
        "struct.pack_into('<H',f,26,3); struct.pack_into('<H',f,28,0xFFFE)\n",
        "struct.pack_into('<H',f,30,9); struct.pack_into('<H',f,32,6)\n",
        "struct.pack_into('<I',f,44,1); struct.pack_into('<I',f,48,1)\n",
        "struct.pack_into('<I',f,56,0x1000)\n",
        "struct.pack_into('<I',f,60,2); struct.pack_into('<I',f,64,1)\n",
        "struct.pack_into('<I',f,68,EOC); struct.pack_into('<I',f,72,0)\n",
        "struct.pack_into('<I',f,76,0)\n",
        "for i in range(1,109): struct.pack_into('<I',f,76+4*i,FREE)\n",
        "fatsec=b''.join(struct.pack('<I',v) for v in fat)\n",
        "f[SS:SS+SS]=fatsec\n",
        "f[2*SS:2*SS+SS]=mdir\n",
        "f[3*SS:3*SS+SS]=b''.join(struct.pack('<I',v) for v in mfat)\n",
        "f[4*SS:4*SS+SS]=bytes(ms)\n",
        "for i in range(10):\n",
        "    f[(5+i)*SS:(5+i)*SS+SS]=big[i*SS:(i+1)*SS]\n",
        "sys.stdout.buffer.write(bytes(f))\n",
    );
    let child = Command::new("python3")
        .args(["-c", script])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("python3");
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "python failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let entries = mscfb::decode::decode(&out.stdout).unwrap();
    assert_eq!(entries.len(), 2);
    let small = entries
        .iter()
        .find(|e| e.name == "Storage 1/Stream Small")
        .expect("small stream");
    assert_eq!(small.data, b"reference mini stream contents");
    let big = entries
        .iter()
        .find(|e| e.name == "Storage 1/Stream Big")
        .expect("big stream");
    let expect: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
    assert_eq!(big.data, expect);
}

#[test]
fn test_mscfb_rejects_truncated_fat_chain() {
    use std::process::Command;

    // Same generator as above but truncates the file mid-data so the
    // FAT chain references a missing sector: decode must fail.
    let script = concat!(
        "import sys, struct\n",
        "SS=512; EOC=0xFFFFFFFE; FREE=0xFFFFFFFF; FATS=0xFFFFFFFD; NOS=0xFFFFFFFF\n",
        "def dirent(name,typ,left,right,child,start,size):\n",
        "    e=bytearray(128)\n",
        "    n=name.encode('utf-16-le')+b'\\x00\\x00'\n",
        "    e[:len(n)]=n\n",
        "    struct.pack_into('<H',e,64,len(n))\n",
        "    e[66]=typ; e[67]=1\n",
        "    struct.pack_into('<I',e,68,left)\n",
        "    struct.pack_into('<I',e,72,right)\n",
        "    struct.pack_into('<I',e,76,child)\n",
        "    struct.pack_into('<I',e,116,start)\n",
        "    struct.pack_into('<Q',e,120,size)\n",
        "    return bytes(e)\n",
        "fat=[FATS,EOC]+[FREE]*126\n",
        "fat[2]=3; fat[3]=EOC\n",
        "mdir=dirent('Root Entry',5,NOS,NOS,1,0,0)\n",
        "mdir+=dirent('S',2,NOS,NOS,NOS,2,5000)\n",
        "f=bytearray(SS+3*SS)\n",
        "f[0:8]=bytes([0xD0,0xCF,0x11,0xE0,0xA1,0xB1,0x1A,0xE1])\n",
        "struct.pack_into('<H',f,26,3); struct.pack_into('<H',f,28,0xFFFE)\n",
        "struct.pack_into('<H',f,30,9); struct.pack_into('<H',f,32,6)\n",
        "struct.pack_into('<I',f,44,1); struct.pack_into('<I',f,48,1)\n",
        "struct.pack_into('<I',f,56,0x1000)\n",
        "struct.pack_into('<I',f,60,EOC); struct.pack_into('<I',f,64,0)\n",
        "struct.pack_into('<I',f,68,EOC); struct.pack_into('<I',f,72,0)\n",
        "struct.pack_into('<I',f,76,0)\n",
        "for i in range(1,109): struct.pack_into('<I',f,76+4*i,FREE)\n",
        "f[SS:SS+SS]=b''.join(struct.pack('<I',v) for v in fat)\n",
        "f[2*SS:2*SS+SS]=mdir\n",
        "sys.stdout.buffer.write(bytes(f))\n",
    );
    let out = Command::new("python3")
        .args(["-c", script])
        .output()
        .expect("python3");
    assert!(out.status.success());
    // stream claims 5000 bytes (regular chain 2->3) but file only has
    // sectors 0..2: chain must hit a missing sector or wrong data.
    assert!(mscfb::decode::decode(&out.stdout).is_err());
}
