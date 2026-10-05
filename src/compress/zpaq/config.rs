//! Compiler for the upstream zpaq config language (the `.cfg` model
//! definition DSL interpreted by upstream `zpaq`'s `Compiler`).
//!
//! A config file has the form:
//!
//! ```text
//! comp hh hm ph pm n
//!   0 icm 22
//!   ...
//! hcomp
//!   <zpaql instructions>
//! post 0 end
//! ```
//!
//! or, with a postprocessor section,
//!
//! ```text
//! pcomp <command> ;
//!   <zpaql instructions>
//! end
//! ```
//!
//! The language is case-insensitive for keywords, uses `( ... )`
//! nested comments, and substitutes `$N+M` with `args[N-1]+M`.
//! Instructions are the ZPAQL opcodes in mnemonic form plus the
//! structured pseudo-operations `if`/`ifnot`/`else`/`endif`,
//! `ifl`/`ifnotl`/`elsel`, and `do`/`while`/`until`/`forever`, which
//! compile to `jt`/`jf`/`jmp`/`lj` jumps exactly as upstream's
//! `libzpaq.cpp` `Compiler` does.
//!
//! [`compile_config`] returns a [`CompiledModel`] holding the COMP
//! section and HCOMP/PCOMP programs, which
//! [`CompiledModel::to_custom_model`] bridges into
//! [`CustomModel`](crate::compress::zpaq::encode::CustomModel) for
//! use with `encode_with_model`.

use alloc::vec::Vec;

use crate::compress::zpaq::encode::CustomModel;
use crate::error::Error;

/// Component mnemonics, upstream `compname[]`.
const COMP_NAMES: &[&str] = &[
    "", "const", "cm", "icm", "match", "avg", "mix2", "mix", "isse", "sse",
];

/// Bytes per COMP record per component type, upstream `compsize[]`.
const COMP_SIZE: &[u8] = &[0, 2, 3, 2, 3, 4, 6, 6, 3, 5];

/// Opcode mnemonics, upstream `opcodelist[]` (indices 0..=255 are the
/// ZPAQL opcodes; 256.. are the compiler pseudo-operations).
const OPCODES: &[&str] = &[
    "error", "a++", "a--", "a!", "a=0", "", "", "a=r", //
    "b<>a", "b++", "b--", "b!", "b=0", "", "", "b=r", //
    "c<>a", "c++", "c--", "c!", "c=0", "", "", "c=r", //
    "d<>a", "d++", "d--", "d!", "d=0", "", "", "d=r", //
    "*b<>a", "*b++", "*b--", "*b!", "*b=0", "", "", "jt", //
    "*c<>a", "*c++", "*c--", "*c!", "*c=0", "", "", "jf", //
    "*d<>a", "*d++", "*d--", "*d!", "*d=0", "", "", "r=a", //
    "halt", "out", "", "hash", "hashd", "", "", "jmp", //
    "a=a", "a=b", "a=c", "a=d", "a=*b", "a=*c", "a=*d", "a=", //
    "b=a", "b=b", "b=c", "b=d", "b=*b", "b=*c", "b=*d", "b=", //
    "c=a", "c=b", "c=c", "c=d", "c=*b", "c=*c", "c=*d", "c=", //
    "d=a", "d=b", "d=c", "d=d", "d=*b", "d=*c", "d=*d", "d=", //
    "*b=a", "*b=b", "*b=c", "*b=d", "*b=*b", "*b=*c", "*b=*d", "*b=", //
    "*c=a", "*c=b", "*c=c", "*c=d", "*c=*b", "*c=*c", "*c=*d", "*c=", //
    "*d=a", "*d=b", "*d=c", "*d=d", "*d=*b", "*d=*c", "*d=*d", "*d=", //
    "", "", "", "", "", "", "", "", //
    "a+=a", "a+=b", "a+=c", "a+=d", "a+=*b", "a+=*c", "a+=*d", "a+=", //
    "a-=a", "a-=b", "a-=c", "a-=d", "a-=*b", "a-=*c", "a-=*d", "a-=", //
    "a*=a", "a*=b", "a*=c", "a*=d", "a*=*b", "a*=*c", "a*=*d", "a*=", //
    "a/=a", "a/=b", "a/=c", "a/=d", "a/=*b", "a/=*c", "a/=*d", "a/=", //
    "a%=a", "a%=b", "a%=c", "a%=d", "a%=*b", "a%=*c", "a%=*d", "a%=", //
    "a&=a", "a&=b", "a&=c", "a&=d", "a&=*b", "a&=*c", "a&=*d", "a&=", //
    "a&~a", "a&~b", "a&~c", "a&~d", "a&~*b", "a&~*c", "a&~*d", "a&~", //
    "a|=a", "a|=b", "a|=c", "a|=d", "a|=*b", "a|=*c", "a|=*d", "a|=", //
    "a^=a", "a^=b", "a^=c", "a^=d", "a^=*b", "a^=*c", "a^=*d", "a^=", //
    "a<<=a", "a<<=b", "a<<=c", "a<<=d", "a<<=*b", "a<<=*c", "a<<=*d", "a<<=", //
    "a>>=a", "a>>=b", "a>>=c", "a>>=d", "a>>=*b", "a>>=*c", "a>>=*d", "a>>=", //
    "a==a", "a==b", "a==c", "a==d", "a==*b", "a==*c", "a==*d", "a==", //
    "a<a", "a<b", "a<c", "a<d", "a<*b", "a<*c", "a<*d", "a<", //
    "a>a", "a>b", "a>c", "a>d", "a>*b", "a>*c", "a>*d", "a>", //
    "", "", "", "", "", "", "", "", //
    "", "", "", "", "", "", "", "lj", //
    "post", "pcomp", "end", "if", "ifnot", "else", "endif", "do", //
    "while", "until", "forever", "ifl", "ifnotl", "elsel", ";",
];

// Pseudo-operation indices into OPCODES (upstream enum CompType).
const JT: usize = 39;
const JF: usize = 47;
const JMP: usize = 63;
const LJ: usize = 255;
const POST: usize = 256;
const PCOMP: usize = 257;
const END: usize = 258;
const IF: usize = 259;
const IFNOT: usize = 260;
const ELSE: usize = 261;
const ENDIF: usize = 262;
const DO: usize = 263;
const WHILE: usize = 264;
const UNTIL: usize = 265;
const FOREVER: usize = 266;
const IFL: usize = 267;
const IFNOTL: usize = 268;
const ELSEL: usize = 269;

/// Maximum IF/DO nesting, matching upstream's fixed `Stack(1000)`.
const MAX_NEST: usize = 1000;

/// A compiled config file: COMP section, HCOMP program, and the
/// optional PCOMP program.
#[derive(Debug, Clone)]
pub struct CompiledModel {
    /// HCOMP memory exponent `hh`.
    pub hh: u8,
    /// HCOMP memory exponent `hm`.
    pub hm: u8,
    /// PCOMP memory exponent `ph` (also present in the COMP header).
    pub ph: u8,
    /// PCOMP memory exponent `pm`.
    pub pm: u8,
    /// `n` followed by the `n` COMP records (no terminator), the
    /// `comp_config` form expected by `CustomModel::new`.
    pub comp: Vec<u8>,
    /// HCOMP opcode stream without the trailing terminator byte.
    pub hcomp: Vec<u8>,
    /// PCOMP opcode stream without terminator, if a `pcomp`
    /// section was compiled.
    pub pcomp: Option<Vec<u8>>,
    /// The raw `pcomp <cmd> ;` command text, if present (e.g. an
    /// external preprocessor command such as `zpipe`). Not part of
    /// the wire format; informational only.
    pub pcomp_cmd: Option<Vec<u8>>,
}

impl CompiledModel {
    /// Bridge into a validated [`CustomModel`] for use with
    /// `encode_with_model`. The wire level byte is derived like
    /// upstream `startBlock`: `2` when the model has no predictor
    /// components, otherwise `1`.
    pub fn to_custom_model(&self) -> Result<CustomModel, Error> {
        let level = if self.comp.first().copied().unwrap_or(0) == 0 {
            2
        } else {
            1
        };
        let model = CustomModel::new(
            level,
            self.hh as usize,
            self.hm as usize,
            self.comp.clone(),
            self.hcomp.clone(),
        )?;
        match &self.pcomp {
            Some(p) => model.with_pcomp(self.ph, self.pm, p.clone()),
            None => Ok(model),
        }
    }
}

/// Header buffer mirroring upstream `ZPAQL` during compilation: a
/// fixed-size header with COMP records at `cend` and the program at
/// `hbegin..hend` (with the 128-byte gap upstream reserves).
struct Header {
    buf: Vec<u8>,
    cend: usize,
    hbegin: usize,
    hend: usize,
}

impl Header {
    fn new() -> Self {
        Self {
            buf: alloc::vec![0u8; 68000],
            cend: 0,
            hbegin: 0,
            hend: 0,
        }
    }
}

/// Config-language parser/compiler: a port of upstream `Compiler`
/// (`libzpaq.cpp`), excluding JIT concerns.
struct Compiler<'a> {
    input: &'a [u8],
    pos: usize,
    args: [i64; 9],
    state: i32,
    if_stack: Vec<usize>,
    do_stack: Vec<usize>,
}

fn tolower(c: u8) -> u8 {
    if c.is_ascii_uppercase() { c + 32 } else { c }
}

impl<'a> Compiler<'a> {
    fn new(input: &'a [u8], args: Option<&[i64; 9]>) -> Self {
        Self {
            input,
            pos: 0,
            args: args.copied().unwrap_or([0; 9]),
            state: 0,
            if_stack: Vec::new(),
            do_stack: Vec::new(),
        }
    }

    /// Advance `pos` to the start of the next token, skipping
    /// whitespace and nested `( ... )` comments (upstream `next`).
    fn next(&mut self) -> Result<(), Error> {
        while self.pos < self.input.len() {
            let c = self.input[self.pos];
            if c == b'(' {
                self.state += 1 + i32::from(self.state < 0);
            } else if self.state > 0 && c == b')' {
                self.state -= 1;
            } else if self.state < 0 && c <= b' ' {
                self.state = 0;
            } else if self.state == 0 && c > b' ' {
                self.state = -1;
                break;
            }
            self.pos += 1;
        }
        if self.pos >= self.input.len() {
            return Err(Error::InvalidData("zpaq config: unexpected end of input"));
        }
        Ok(())
    }

    /// True when the token at `pos` equals `word` (case-insensitive,
    /// delimited by whitespace or `(`), upstream `matchToken`.
    fn match_token(&self, word: &str) -> bool {
        let mut i = self.pos;
        for &w in word.as_bytes() {
            if i >= self.input.len() || self.input[i] <= b' ' || self.input[i] == b'(' {
                return false;
            }
            if tolower(self.input[i]) != tolower(w) {
                return false;
            }
            i += 1;
        }
        i >= self.input.len() || self.input[i] <= b' ' || self.input[i] == b'('
    }

    /// Read a token that must be in `list`; returns its index
    /// (upstream `rtoken(const char* list[])`).
    fn rtoken_list(&mut self, list: &[&str]) -> Result<usize, Error> {
        self.next()?;
        for (i, word) in list.iter().enumerate() {
            if self.match_token(word) {
                return Ok(i);
            }
        }
        Err(Error::InvalidData("zpaq config: unexpected token"))
    }

    /// Read a token that must equal `s` (upstream `rtoken(const char* s)`).
    fn rtoken_str(&mut self, s: &str) -> Result<(), Error> {
        self.next()?;
        if !self.match_token(s) {
            return Err(Error::InvalidData("zpaq config: unexpected token"));
        }
        Ok(())
    }

    /// Parse a leading integer with C `atoi` semantics: optional `-`,
    /// then decimal digits; parsing stops at the first non-digit.
    fn atoi(&self, mut i: usize) -> i64 {
        let neg = self.input.get(i) == Some(&b'-');
        if neg {
            i += 1;
        }
        let mut v: i64 = 0;
        while let Some(&c) = self.input.get(i) {
            if !c.is_ascii_digit() {
                break;
            }
            v = v.saturating_mul(10).saturating_add(i64::from(c - b'0'));
            i += 1;
        }
        if neg { -v } else { v }
    }

    /// Read a number in `low..=high`, with `$N+M` substitution
    /// (`args[N-1]+M`, upstream `rtoken(int low, int high)`).
    fn rtoken_num(&mut self, low: i64, high: i64) -> Result<i64, Error> {
        self.next()?;
        let c = self.input[self.pos];
        let r = if c == b'$'
            && self
                .input
                .get(self.pos + 1)
                .is_some_and(|d| (b'1'..=b'9').contains(d))
        {
            let mut r = 0i64;
            if self.input.get(self.pos + 2) == Some(&b'+') {
                r = self.atoi(self.pos + 3);
            }
            r + self.args[usize::from(self.input[self.pos + 1] - b'1')]
        } else if c == b'-' || c.is_ascii_digit() {
            self.atoi(self.pos)
        } else {
            return Err(Error::InvalidData("zpaq config: expected a number"));
        };
        if r < low {
            return Err(Error::InvalidData("zpaq config: number too low"));
        }
        if r > high {
            return Err(Error::InvalidData("zpaq config: number too high"));
        }
        Ok(r)
    }

    fn push(stack: &mut Vec<usize>, v: usize) -> Result<(), Error> {
        if stack.len() >= MAX_NEST {
            return Err(Error::InvalidData("zpaq config: IF or DO nested too deep"));
        }
        stack.push(v);
        Ok(())
    }

    fn pop(stack: &mut Vec<usize>) -> Result<usize, Error> {
        stack
            .pop()
            .ok_or(Error::InvalidData("zpaq config: unmatched IF or DO"))
    }

    /// Compile an HCOMP or PCOMP program into `z` until `post`,
    /// `pcomp`, or `end`; returns the terminating token index
    /// (upstream `compile_comp`). The structured pseudo-operations
    /// lower to `jt`/`jf`/`jmp`/`lj` with patched operands.
    fn compile_comp(&mut self, z: &mut Header) -> Result<usize, Error> {
        let comp_begin = z.hend;
        let mut op;
        loop {
            op = self.rtoken_list(OPCODES)?;
            if op == POST || op == PCOMP || op == END {
                break;
            }
            let mut operand = -1i32;
            let mut operand2 = -1i32;
            if op == IF {
                op = JF;
                operand = 0;
                Self::push(&mut self.if_stack, z.hend + 1)?;
            } else if op == IFNOT {
                op = JT;
                operand = 0;
                Self::push(&mut self.if_stack, z.hend + 1)?;
            } else if op == IFL || op == IFNOTL {
                z.buf[z.hend] = if op == IFL { JT } else { JF } as u8;
                z.hend += 1;
                z.buf[z.hend] = 3;
                z.hend += 1;
                op = LJ;
                operand = 0;
                operand2 = 0;
                Self::push(&mut self.if_stack, z.hend + 1)?;
            } else if op == ELSE || op == ELSEL {
                if op == ELSE {
                    op = JMP;
                    operand = 0;
                } else {
                    op = LJ;
                    operand = 0;
                    operand2 = 0;
                }
                let a = Self::pop(&mut self.if_stack)?;
                if a <= comp_begin || a >= z.hend {
                    return Err(Error::InvalidData("zpaq config: unmatched IF"));
                }
                if z.buf[a - 1] != LJ as u8 {
                    let j = z.hend - a + 1 + usize::from(op == LJ);
                    if j > 127 {
                        return Err(Error::InvalidData(
                            "zpaq config: IF too big, use IFL/IFNOTL",
                        ));
                    }
                    z.buf[a] = j as u8;
                } else {
                    let j = z.hend - comp_begin + 2 + usize::from(op == LJ);
                    z.buf[a] = (j & 255) as u8;
                    z.buf[a + 1] = ((j >> 8) & 255) as u8;
                }
                Self::push(&mut self.if_stack, z.hend + 1)?;
            } else if op == ENDIF {
                let a = Self::pop(&mut self.if_stack)?;
                if a <= comp_begin || a >= z.hend {
                    return Err(Error::InvalidData("zpaq config: unmatched IF"));
                }
                let j = z.hend - a - 1;
                if z.buf[a - 1] != LJ as u8 {
                    if j > 127 {
                        return Err(Error::InvalidData(
                            "zpaq config: IF too big, use IFL/IFNOTL/ELSEL",
                        ));
                    }
                    z.buf[a] = j as u8;
                } else {
                    let j = z.hend - comp_begin;
                    z.buf[a] = (j & 255) as u8;
                    z.buf[a + 1] = ((j >> 8) & 255) as u8;
                }
            } else if op == DO {
                Self::push(&mut self.do_stack, z.hend)?;
            } else if op == WHILE || op == UNTIL || op == FOREVER {
                let a = Self::pop(&mut self.do_stack)?;
                if a < comp_begin || a >= z.hend {
                    return Err(Error::InvalidData("zpaq config: unmatched DO"));
                }
                let j = a as i64 - z.hend as i64 - 2;
                if j >= -127 {
                    op = match op {
                        WHILE => JT,
                        UNTIL => JF,
                        _ => JMP,
                    };
                    operand = (j & 255) as i32;
                } else {
                    let j = a - comp_begin;
                    if j > z.hend - comp_begin {
                        return Err(Error::InvalidData("zpaq config: bad jump"));
                    }
                    if op == WHILE {
                        z.buf[z.hend] = JF as u8;
                        z.hend += 1;
                        z.buf[z.hend] = 3;
                        z.hend += 1;
                    } else if op == UNTIL {
                        z.buf[z.hend] = JT as u8;
                        z.hend += 1;
                        z.buf[z.hend] = 3;
                        z.hend += 1;
                    }
                    op = LJ;
                    operand = (j & 255) as i32;
                    operand2 = (j >> 8) as i32;
                }
            } else if op & 7 == 7 {
                if op == LJ {
                    let v = self.rtoken_num(0, 65535)?;
                    operand = (v & 255) as i32;
                    operand2 = (v >> 8) as i32;
                } else if op == JT || op == JF || op == JMP {
                    operand = (self.rtoken_num(-128, 127)? & 255) as i32;
                } else {
                    operand = self.rtoken_num(0, 255)? as i32;
                }
            }
            if (0..=255).contains(&op) {
                z.buf[z.hend] = op as u8;
                z.hend += 1;
            }
            if operand >= 0 {
                z.buf[z.hend] = operand as u8;
                z.hend += 1;
            }
            if operand2 >= 0 {
                z.buf[z.hend] = operand2 as u8;
                z.hend += 1;
            }
            if z.hend >= z.buf.len() - 130 || z.hend - z.hbegin + z.cend - 2 > 65535 {
                return Err(Error::InvalidData("zpaq config: program too big"));
            }
        }
        z.buf[z.hend] = 0;
        z.hend += 1;
        Ok(op)
    }

    /// Compile a full config into a [`CompiledModel`]
    /// (upstream `Compiler` constructor).
    fn compile(&mut self) -> Result<CompiledModel, Error> {
        let mut hz = Header::new();
        self.rtoken_str("comp")?;
        hz.buf[2] = self.rtoken_num(0, 255)? as u8; // hh
        hz.buf[3] = self.rtoken_num(0, 255)? as u8; // hm
        hz.buf[4] = self.rtoken_num(0, 255)? as u8; // ph
        hz.buf[5] = self.rtoken_num(0, 255)? as u8; // pm
        let n = self.rtoken_num(0, 255)?;
        hz.buf[6] = n as u8;
        hz.cend = 7;
        for i in 0..n {
            self.rtoken_num(i, i)?;
            let ty = self.rtoken_list(COMP_NAMES)?;
            hz.buf[hz.cend] = ty as u8;
            hz.cend += 1;
            let clen = usize::from(COMP_SIZE[ty & 255]);
            if !(1..=10).contains(&clen) {
                return Err(Error::InvalidData("zpaq config: invalid component"));
            }
            for _ in 1..clen {
                hz.buf[hz.cend] = self.rtoken_num(0, 255)? as u8;
                hz.cend += 1;
            }
        }
        hz.cend += 1; // COMP terminator
        hz.hbegin = hz.cend + 128;
        hz.hend = hz.hbegin;

        self.rtoken_str("hcomp")?;
        let op = self.compile_comp(&mut hz)?;

        let hsize = hz.cend - 2 + hz.hend - hz.hbegin;
        hz.buf[0] = (hsize & 255) as u8;
        hz.buf[1] = (hsize >> 8) as u8;

        let mut pcomp = None;
        let mut pcomp_cmd = None;
        if op == POST {
            self.rtoken_num(0, 0)?;
            self.rtoken_str("end")?;
        } else if op == PCOMP {
            let mut pz = Header::new();
            pz.buf[4] = hz.buf[4];
            pz.buf[5] = hz.buf[5];
            pz.cend = 8;
            pz.hbegin = pz.cend + 128;
            pz.hend = pz.hbegin;

            // pcomp_cmd: raw bytes up to ';' (case sensitive).
            self.next()?;
            let start = self.pos;
            while self.pos < self.input.len() && self.input[self.pos] != b';' {
                self.pos += 1;
            }
            let cmd = self.input[start..self.pos].to_vec();
            if self.pos < self.input.len() {
                self.pos += 1;
            }
            pcomp_cmd = Some(cmd);

            let pend = self.compile_comp(&mut pz)?;
            if pend != END {
                return Err(Error::InvalidData("zpaq config: expected END"));
            }
            pcomp = Some(pz.buf[pz.hbegin..pz.hend - 1].to_vec());
        } else if op != END {
            return Err(Error::InvalidData(
                "zpaq config: expected END or POST 0 END or PCOMP",
            ));
        }

        Ok(CompiledModel {
            hh: hz.buf[2],
            hm: hz.buf[3],
            ph: hz.buf[4],
            pm: hz.buf[5],
            comp: hz.buf[6..hz.cend - 1].to_vec(),
            hcomp: hz.buf[hz.hbegin..hz.hend - 1].to_vec(),
            pcomp,
            pcomp_cmd,
        })
    }
}

/// Compile a config-language source into a [`CompiledModel`],
/// with `$1`..`$9` substitutions reading zero (upstream `args = NULL`).
pub fn compile_config(source: &[u8]) -> Result<CompiledModel, Error> {
    Compiler::new(source, None).compile()
}

/// Compile with `$N` substitution arguments (`$N+M` reads
/// `args[N-1]+M`), matching upstream `Compiler`'s `args` parameter.
pub fn compile_config_with_args(source: &[u8], args: &[i64; 9]) -> Result<CompiledModel, Error> {
    Compiler::new(source, Some(args)).compile()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// min.cfg equivalent: compiles to the level-1 built-in blob.
    const MIN_CFG: &[u8] = b"comp 1 2 0 0 2\n  0 icm 16\n  1 isse 19 0\nhcomp\n  *b=a a=0 d=0 hash b-- hash *d=a\n  d++ b-- hash b-- hash *d=a\n  halt\npost 0 end\n";

    /// Functional text of upstream mid.cfg (zpaq 1.07+ distribution,
    /// comments stripped).
    const MID_CFG: &[u8] = b"(zpaq 1.07+ config file tuned for average compression.)\ncomp 3 3 0 0 8 (hh hm ph pm n)\n  0 icm 5\n  1 isse 13 0\n  2 isse $1+17 1\n  3 isse $1+18 2\n  4 isse $1+18 3\n  5 isse $1+19 4\n  6 match $1+22 $1+24\n  7 mix 16 0 7 24 255\nhcomp\n  c++ *c=a b=c a=0\n  d= 1 hash *d=a\n  b-- d++ hash *d=a\n  b-- d++ hash *d=a\n  b-- d++ hash *d=a\n  b-- d++ hash *d=a\n  b-- d++ hash b-- hash *d=a\n  d++ a=*c a<<= 8 *d=a\n  halt\npost\n  0\nend\n";

    /// Functional text of upstream max.cfg (zpaq 1.07+ distribution,
    /// comments stripped).
    const MAX_CFG: &[u8] = b"(zpaq 1.07+ config file tuned for high compression)\ncomp 5 9 0 0 22\n  0 const 160\n  1 icm 5\n  2 isse 13 1\n  3 isse $1+16 2\n  4 isse $1+18 3\n  5 isse $1+19 4\n  6 isse $1+19 5\n  7 isse $1+20 6\n  8 match $1+22 $1+24\n  9 icm $1+17\n  10 isse $1+19 9\n  11 icm 13\n  12 icm 13\n  13 icm 13\n  14 icm 14\n  15 mix 16 0 15 24 255\n  16 mix 8 0 16 10 255\n  17 mix2 0 15 16 24 0\n  18 sse 8 17 32 255\n  19 mix2 8 17 18 16 255\n  20 sse 16 19 32 255\n  21 mix2 0 19 20 16 0\nhcomp\n  c++ *c=a b=c a=0\n  d= 2 hash *d=a b--\n  d++ hash *d=a b--\n  d++ hash *d=a b--\n  d++ hash *d=a b--\n  d++ hash *d=a b--\n  d++ hash b-- hash *d=a b--\n  d++ hash *d=a b--\n  d++ a=*c a&~ 32\n  a> 64 if\n  a< 91 if\n  d++ hashd d--\n  *d<>a a+=*d a*= 20 *d=a\n  jmp 9\n  endif\n  endif\n  a=*d a== 0 ifnot\n  d++ *d=a d--\n  endif\n  *d=0\n  d++\n  d++ b=c b-- a=0 hash *d=a\n  d++ b-- a=0 hash *d=a\n  d++ b-- a=0 hash *d=a\n  d++ a=b a-= 212 b=a a=0 hash\n  *d=a b<>a a-= 216 b<>a a=*b a&= 60 hashd\n  d++ a=*c a<<= 9 *d=a\n  d++\n  d++\n  d++ d++\n  d++ *d=a\n  halt\npost\n  0\nend\n";

    /// Compile `src` and rebuild the complete wire header blob
    /// (`hsize[2] hh hm ph pm n` + records + `0` + hcomp + `0`).
    fn blob(src: &[u8]) -> Vec<u8> {
        let m = compile_config(src).unwrap();
        let mut b = Vec::new();
        let hsize = 4 + m.comp.len() + 1 + m.hcomp.len() + 1;
        b.push((hsize & 255) as u8);
        b.push((hsize >> 8) as u8);
        b.extend_from_slice(&[m.hh, m.hm, m.ph, m.pm]);
        b.extend_from_slice(&m.comp);
        b.push(0);
        b.extend_from_slice(&m.hcomp);
        b.push(0);
        b
    }

    #[test]
    fn compiles_builtin_models_byte_exact() {
        use crate::compress::zpaq::models;
        assert_eq!(blob(MIN_CFG), models::MODEL_LEVEL1);
        assert_eq!(blob(MID_CFG), models::MODEL_LEVEL2);
        assert_eq!(blob(MAX_CFG), models::MODEL_LEVEL3);
    }

    #[test]
    fn mid_cfg_args_shift_table_sizes() {
        // $1=1 bumps every $1-derived size argument by one.
        let base = compile_config(MID_CFG).unwrap();
        let m = compile_config_with_args(MID_CFG, &[1, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        // isse $1+17 1 -> 18, etc; comp differs but hcomp is identical.
        assert_ne!(base.comp, m.comp);
        assert_eq!(base.hcomp, m.hcomp);
        assert_eq!(m.comp[7], 18); // first arg of component 2 (isse $1+17)
    }

    #[test]
    fn pcomp_section_compiles() {
        let src = b"comp 1 8 8 8 1\n  0 icm 8\nhcomp\n  halt\npcomp zpipe ;\n  a++ out halt\nend\n";
        let m = compile_config(src).unwrap();
        assert_eq!(m.pcomp.as_deref(), Some(&[1, 57, 56][..])); // a++ out halt
        assert_eq!(m.pcomp_cmd.as_deref(), Some(b"zpipe ".as_slice()));
    }

    #[test]
    fn structured_control_flow() {
        // if/else/endif lowers to jf + jmp with patched offsets.
        let src = b"comp 0 0 0 0 0\nhcomp\n  a= 1\n  if\n    a++\n  else\n    a--\n  endif\n  halt\nend\n";
        let m = compile_config(src).unwrap();
        // a= 1 -> 71,1 ; if -> jf(47),+3 ; a++ -> 1 ; else -> jmp(63),+1 ; a-- -> 2 ; halt -> 56
        assert_eq!(m.hcomp, [71, 1, 47, 3, 1, 63, 1, 2, 56]);
    }

    #[test]
    fn do_while_lowers_to_backward_jt() {
        let src = b"comp 0 0 0 0 0\nhcomp\n  a= 3\n  do\n    a--\n    a> 0\n  while\n  halt\nend\n";
        let m = compile_config(src).unwrap();
        // a= 3 -> 71,3 ; a-- -> 2 ; a> 0 -> 239,0 ; while -> jt(39),-5
        assert_eq!(m.hcomp, [71, 3, 2, 239, 0, 39, 251, 56]);
    }

    #[test]
    fn errors_on_malformed_input() {
        assert!(compile_config(b"hcomp halt end").is_err()); // missing comp
        assert!(compile_config(b"comp 0 0 0 0 0\nhcomp\n  endif\nend\n").is_err()); // unmatched if
        assert!(compile_config(b"comp 0 0 0 0 0\nhcomp\n  while\nend\n").is_err()); // unmatched do
        assert!(compile_config(b"comp 0 0 0 0 1\n  0 bogus\nhcomp halt end").is_err()); // bad component
        assert!(compile_config(b"comp 0 0 0 0 0\nhcomp\n  a= 300\nend\n").is_err()); // operand range
        assert!(compile_config(b"comp 0 0 0 0 0\nhcomp\n  halt\n").is_err()); // missing end
    }

    #[test]
    fn compiled_model_encodes_identically_to_builtin() {
        // End-to-end: compiling mid.cfg and encoding through
        // CustomModel produces the same stream as `encode` level 2.
        let m = compile_config(MID_CFG).unwrap().to_custom_model().unwrap();
        let data = b"config compiled model";
        let a = crate::compress::zpaq::encode::encode(data, 2);
        let b = crate::compress::zpaq::encode::encode_with_model(data, &m).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn case_insensitive_and_nested_comments() {
        let src = b"(outer (nested) comment)\nCOMP 1 2 0 0 2\n  0 ICM 16\n  1 ISSE 19 0\nHCOMP\n  HALT\nPOST 0 END\n";
        let m = compile_config(src).unwrap();
        assert_eq!(m.hh, 1);
        assert_eq!(m.comp, [2, 3, 16, 8, 19, 0]);
        assert_eq!(m.hcomp, [56]);
    }
}
