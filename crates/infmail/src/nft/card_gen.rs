//! card_gen.rs — генерация дизайна NFT-карточки (порт designs.ts из nft-card-studio).
//!
//! Точный порт `randomPopConfig()` + `drawPop()` (designs.ts:310-353, 94-167):
//!   - 5 случайных layouts (coral/citrus/grape/ocean/blush) — позиции блобов
//!   - HSL random: hue=rand(0,360), sat=rand(58,88), light=rand(48,66)
//!   - analogous (50%) или complementary оттенок для второго цвета
//!   - плашка (plate): тёмный стеклянный прямоугольник rx=30, светлый текст Roboto 900
//!   - тег provider снизу (Space Mono), хром-бар "№ tokenId", полный username внизу

use serde_json::{json, Value};

pub const W: u32 = 1000;
pub const H: u32 = 1000;

#[derive(Clone, Debug)]
pub enum ShapeKind {
    Circle,
    Arc,
}

#[derive(Clone, Debug)]
pub struct Shape {
    pub kind: ShapeKind,
    pub x: f64,
    pub y: f64,
    pub r: f64,
    pub a0: f64,
    pub a1: f64,
    /// "light" → rgba(255,255,255,alpha), "dark" → rgba(0,0,0,alpha)
    pub light: bool,
    pub alpha: f64,
    pub drift: f64,
}

#[derive(Clone, Debug)]
pub struct PopConfig {
    pub id: String,
    /// c1, c2, gx0, gy0, gx1, gy1
    pub gradient: (String, String, f64, f64, f64, f64),
    pub shapes: Vec<Shape>,
    pub plate_bg: (String, String),
    pub plate_text: String,
    pub provider_text: String,
    pub chrome_color: String,
    pub full_name_color: String,
    pub grain: bool,
}

/// Равномерный простой RNG (xorshift) — детерминированный, без внешнего rand в nft-модуле.
pub struct Rng {
    state: u64,
}

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self { state: seed.max(1) }
    }
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }
    pub fn range(&mut self, min: f64, max: f64) -> f64 {
        let r = (self.next_u64() as f64) / (u64::MAX as f64);
        min + r * (max - min)
    }
    pub fn rng_in_range(&mut self, min: i64, max: i64) -> f64 {
        self.range(min as f64, max as f64)
    }
}

fn hsl(h: f64, s: f64, l: f64) -> String {
    format!("hsl({:.0}, {:.0}%, {:.0}%)", h, s, l)
}
fn hsla(h: f64, s: f64, l: f64, a: f64) -> String {
    format!("hsla({:.0}, {:.0}%, {:.0}%, {})", h, s, l, a)
}

/// 5 layouts — порт RANDOM_LAYOUTS из designs.ts:261-304.
#[allow(clippy::type_complexity)] // GATE: layout table type is local to the designer
fn layouts() -> Vec<(
    Vec<(ShapeKind, f64, f64, f64, f64, f64, bool, f64, f64)>,
    (f64, f64, f64, f64),
    bool,
)> {
    vec![
        // coral-like
        (
            vec![
                (
                    ShapeKind::Circle,
                    0.14,
                    0.86,
                    260.0,
                    0.0,
                    0.0,
                    false,
                    0.32,
                    6.0,
                ),
                (
                    ShapeKind::Circle,
                    0.92,
                    0.10,
                    200.0,
                    0.0,
                    0.0,
                    true,
                    0.30,
                    8.0,
                ),
            ],
            (0.0, 0.0, 0.0, 1.0),
            false,
        ),
        // citrus-like
        (
            vec![
                (
                    ShapeKind::Circle,
                    0.16,
                    0.18,
                    300.0,
                    0.0,
                    0.0,
                    true,
                    0.28,
                    10.0,
                ),
                (
                    ShapeKind::Circle,
                    0.90,
                    0.92,
                    170.0,
                    0.0,
                    0.0,
                    false,
                    0.30,
                    6.0,
                ),
            ],
            (0.0, 0.0, 1.0, 1.0),
            true,
        ),
        // grape-like
        (
            vec![
                (
                    ShapeKind::Arc,
                    0.50,
                    1.05,
                    480.0,
                    std::f64::consts::PI,
                    0.0,
                    false,
                    0.22,
                    0.0,
                ),
                (
                    ShapeKind::Circle,
                    0.22,
                    0.28,
                    140.0,
                    0.0,
                    0.0,
                    true,
                    0.18,
                    8.0,
                ),
            ],
            (0.0, 0.0, 1.0, 0.2),
            false,
        ),
        // ocean-like
        (
            vec![
                (
                    ShapeKind::Arc,
                    0.50,
                    -0.05,
                    460.0,
                    0.0,
                    std::f64::consts::PI,
                    true,
                    0.16,
                    0.0,
                ),
                (
                    ShapeKind::Circle,
                    0.85,
                    0.80,
                    130.0,
                    0.0,
                    0.0,
                    false,
                    0.32,
                    6.0,
                ),
            ],
            (0.0, 1.0, 1.0, 0.0),
            true,
        ),
        // blush-like
        (
            vec![
                (
                    ShapeKind::Circle,
                    0.78,
                    0.22,
                    260.0,
                    0.0,
                    0.0,
                    true,
                    0.30,
                    8.0,
                ),
                (
                    ShapeKind::Circle,
                    0.20,
                    0.90,
                    200.0,
                    0.0,
                    0.0,
                    false,
                    0.28,
                    5.0,
                ),
            ],
            (0.0, 0.0, 0.3, 1.0),
            false,
        ),
    ]
}

/// Порт randomPopConfig() — designs.ts:310-353.
pub fn random_pop_config(seed: u64) -> PopConfig {
    let mut rng = Rng::new(seed);
    let layouts = layouts();
    let li = (rng.next_u64() % 5) as usize;
    let (shape_specs, gdir, grain) = layouts[li].clone();

    let h1 = rng.range(0.0, 360.0);
    let analogous = rng.range(0.0, 1.0) < 0.5;
    let h2 = if analogous {
        h1 + rng.range(-35.0, 35.0)
    } else {
        let dir = if rng.range(0.0, 1.0) < 0.5 { 1.0 } else { -1.0 };
        h1 + rng.range(120.0, 200.0) * dir
    };
    let s1 = rng.range(58.0, 88.0);
    let l1 = rng.range(48.0, 66.0);
    let s2 = rng.range(55.0, 85.0);
    let l2 = rng.range(32.0, 54.0);
    let c1 = hsl(h1, s1, l1);
    let c2 = hsl(h2, s2, l2);

    let plate_bg = (hsla(h1, 45.0, 10.0, 0.9), hsla(h2, 40.0, 16.0, 0.9));

    let shapes: Vec<Shape> = shape_specs
        .iter()
        .map(|(kind, x, y, r, a0, a1, light, alpha, drift)| Shape {
            kind: kind.clone(),
            x: *x,
            y: *y,
            r: *r,
            a0: *a0,
            a1: *a1,
            light: *light,
            alpha: *alpha,
            drift: *drift,
        })
        .collect();

    PopConfig {
        id: "randompop".into(),
        gradient: (c1, c2, gdir.0, gdir.1, gdir.2, gdir.3),
        shapes,
        plate_bg,
        plate_text: "#ffffff".into(),
        provider_text: "rgba(255,255,255,0.92)".into(),
        chrome_color: "rgba(255,255,255,0.7)".into(),
        full_name_color: "rgba(255,255,255,0.45)".into(),
        grain,
    }
}

/// Собрать JSON-описание карточки (для /verify и тестов) — параметры дизайна.
pub fn config_json(cfg: &PopConfig, username: &str, token_id: u64) -> Value {
    json!({
        "design": cfg.id,
        "username": username,
        "tokenId": token_id,
        "gradient": [cfg.gradient.0, cfg.gradient.1],
        "grain": cfg.grain,
    })
}

/// Числовой seed из email+tokenId — стабильная генерация (одна и та же карточка).
pub fn seed_for(email: &str, token_id: u64) -> u64 {
    let s = format!("{email}:{token_id}");
    let mut h = 0xcbf29ce484222325u64;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}
