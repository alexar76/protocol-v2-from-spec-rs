//! JSON that keeps number literals. Parsing `0.0` as a float and printing `0`
//! changes the manifest digest (§7.3.2, §7.3.3).

#[derive(Clone, Debug, PartialEq)]
pub enum J {
    Null,
    Bool(bool),
    Num(String),
    Str(String),
    Arr(Vec<J>),
    Obj(Vec<(String, J)>),
}

impl J {
    pub fn get(&self, key: &str) -> Option<&J> {
        match self {
            J::Obj(pairs) => pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            J::Str(s) => Some(s),
            _ => None,
        }
    }
}

pub fn parse(text: &str) -> Result<J, String> {
    let mut p = Parser { s: text, i: 0 };
    let value = p.parse_value()?;
    p.skip_ws();
    if !p.eof() {
        return Err("trailing data".into());
    }
    Ok(value)
}

/// Python `json.dumps(..., sort_keys=True, ensure_ascii=False)` with default separators.
pub fn emit_spaced(v: &J) -> String {
    emit(v, ", ", ": ")
}

struct Parser<'a> {
    s: &'a str,
    i: usize,
}

impl<'a> Parser<'a> {
    fn eof(&self) -> bool {
        self.i >= self.s.len()
    }
    fn rest(&self) -> &str {
        &self.s[self.i..]
    }
    fn skip_ws(&mut self) {
        while let Some(c) = self.rest().chars().next() {
            if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
                self.i += c.len_utf8();
            } else {
                break;
            }
        }
    }
    fn eat(&mut self, lit: &str) -> Result<(), String> {
        if self.rest().starts_with(lit) {
            self.i += lit.len();
            Ok(())
        } else {
            Err(format!("expected {lit}"))
        }
    }
    fn parse_value(&mut self) -> Result<J, String> {
        self.skip_ws();
        let c = self.rest().chars().next().ok_or("eof")?;
        match c {
            '{' => self.parse_object(),
            '[' => self.parse_array(),
            '"' => Ok(J::Str(self.parse_string()?)),
            't' => {
                self.eat("true")?;
                Ok(J::Bool(true))
            }
            'f' => {
                self.eat("false")?;
                Ok(J::Bool(false))
            }
            'n' => {
                self.eat("null")?;
                Ok(J::Null)
            }
            _ => Ok(J::Num(self.parse_number()?)),
        }
    }
    fn parse_object(&mut self) -> Result<J, String> {
        self.eat("{")?;
        let mut pairs = Vec::new();
        self.skip_ws();
        if self.rest().starts_with('}') {
            self.i += 1;
            return Ok(J::Obj(pairs));
        }
        loop {
            self.skip_ws();
            let key = self.parse_string()?;
            self.skip_ws();
            self.eat(":")?;
            pairs.push((key, self.parse_value()?));
            self.skip_ws();
            if self.rest().starts_with('}') {
                self.i += 1;
                return Ok(J::Obj(pairs));
            }
            self.eat(",")?;
        }
    }
    fn parse_array(&mut self) -> Result<J, String> {
        self.eat("[")?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.rest().starts_with(']') {
            self.i += 1;
            return Ok(J::Arr(items));
        }
        loop {
            items.push(self.parse_value()?);
            self.skip_ws();
            if self.rest().starts_with(']') {
                self.i += 1;
                return Ok(J::Arr(items));
            }
            self.eat(",")?;
        }
    }
    fn parse_number(&mut self) -> Result<String, String> {
        let start = self.i;
        let b = self.s.as_bytes();
        if b.get(self.i) == Some(&b'-') {
            self.i += 1;
        }
        if b.get(self.i) == Some(&b'0') {
            self.i += 1;
        } else if b.get(self.i).is_some_and(|c| c.is_ascii_digit()) {
            while b.get(self.i).is_some_and(|c| c.is_ascii_digit()) {
                self.i += 1;
            }
        } else {
            return Err("bad number".into());
        }
        if b.get(self.i) == Some(&b'.') {
            self.i += 1;
            if !b.get(self.i).is_some_and(|c| c.is_ascii_digit()) {
                return Err("bad fraction".into());
            }
            while b.get(self.i).is_some_and(|c| c.is_ascii_digit()) {
                self.i += 1;
            }
        }
        if b.get(self.i) == Some(&b'e') || b.get(self.i) == Some(&b'E') {
            self.i += 1;
            if b.get(self.i) == Some(&b'+') || b.get(self.i) == Some(&b'-') {
                self.i += 1;
            }
            while b.get(self.i).is_some_and(|c| c.is_ascii_digit()) {
                self.i += 1;
            }
        }
        Ok(self.s[start..self.i].to_string())
    }
    fn parse_string(&mut self) -> Result<String, String> {
        self.eat("\"")?;
        let mut out = String::new();
        loop {
            let ch = self.rest().chars().next().ok_or("unterminated string")?;
            self.i += ch.len_utf8();
            if ch == '"' {
                return Ok(out);
            }
            if ch != '\\' {
                out.push(ch);
                continue;
            }
            let e = self.rest().chars().next().ok_or("bad escape")?;
            self.i += e.len_utf8();
            match e {
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                '/' => out.push('/'),
                'b' => out.push('\u{0008}'),
                'f' => out.push('\u{000c}'),
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                'u' => {
                    let hex = self.s.get(self.i..self.i + 4).ok_or("bad unicode")?;
                    self.i += 4;
                    let code = u32::from_str_radix(hex, 16).map_err(|_| "bad unicode")?;
                    out.push(char::from_u32(code).ok_or("bad unicode")?);
                }
                _ => return Err("bad escape".into()),
            }
        }
    }
}

fn emit(v: &J, item_sep: &str, key_sep: &str) -> String {
    match v {
        J::Null => "null".into(),
        J::Bool(true) => "true".into(),
        J::Bool(false) => "false".into(),
        J::Num(n) => n.clone(),
        J::Str(s) => quote(s),
        J::Arr(xs) => {
            let parts: Vec<_> = xs.iter().map(|x| emit(x, item_sep, key_sep)).collect();
            format!("[{}]", parts.join(item_sep))
        }
        J::Obj(pairs) => {
            let mut pairs = pairs.clone();
            pairs.sort_by(|a, b| a.0.cmp(&b.0));
            let parts: Vec<_> = pairs
                .iter()
                .map(|(k, val)| format!("{}{key_sep}{}", quote(k), emit(val, item_sep, key_sep)))
                .collect();
            format!("{{{}}}", parts.join(item_sep))
        }
    }
}

fn quote(s: &str) -> String {
    let mut out = String::from("\"");
    for ch in s.chars() {
        match ch {
            '"' | '\\' => {
                out.push('\\');
                out.push(ch);
            }
            '\u{0008}' => out.push_str("\\b"),
            '\u{000c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
