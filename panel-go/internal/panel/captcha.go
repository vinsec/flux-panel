package panel

import (
	"bytes"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"fmt"
	"golang.org/x/image/font"
	"golang.org/x/image/font/opentype"
	"golang.org/x/image/math/fixed"
	"image"
	"image/color"
	"image/draw"
	_ "image/jpeg"
	"image/png"
	"math"
	"math/big"
	"sync"
	"time"
)

// Assets are the existing Java application's bundled resources, used locally.
//
//go:embed captcha-assets/*
var captchaAssets embed.FS

type challenge struct {
	Kind     string
	Expiry   int64
	Verified bool
	X        float64
	Points   []image.Point
}
type captchas struct {
	mu    sync.Mutex
	items map[string]challenge
}

func newCaptchas() *captchas { return &captchas{items: map[string]challenge{}} }
func (c *captchas) expire(instant int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, v := range c.items {
		if v.Expiry < instant {
			delete(c.items, id)
		}
	}
}
func (c *captchas) consume(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.items[id]
	delete(c.items, id)
	return ok && v.Expiry > now() && v.Verified
}
func randomInt(n int) int {
	v, e := rand.Int(rand.Reader, big.NewInt(int64(n)))
	must(e)
	return int(v.Int64())
}
func pngURL(img image.Image) string {
	var b bytes.Buffer
	must(png.Encode(&b, img))
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(b.Bytes())
}
func captchaBackground() *image.RGBA {
	b, e := captchaAssets.ReadFile(fmt.Sprintf("captcha-assets/%d.jpg", 1+randomInt(26)))
	must(e)
	src, _, e := image.Decode(bytes.NewReader(b))
	must(e)
	dst := image.NewRGBA(image.Rect(0, 0, 300, 180))
	for y := 0; y < 180; y++ {
		for x := 0; x < 300; x++ {
			dst.Set(x, y, src.At(src.Bounds().Min.X+x*src.Bounds().Dx()/300, src.Bounds().Min.Y+y*src.Bounds().Dy()/180))
		}
	}
	return dst
}
func drawWord(dst draw.Image, text string, x, y, size int) {
	f := cachedCaptchaFont()
	face, e := opentype.NewFace(f, &opentype.FaceOptions{Size: float64(size), DPI: 72, Hinting: font.HintingFull})
	must(e)
	defer face.Close()
	d := font.Drawer{Dst: dst, Src: image.NewUniform(color.RGBA{240, 35, 50, 255}), Face: face, Dot: fixed.P(x, y)}
	d.DrawString(text)
}
func (p *Panel) captchaAPI(s store, b M, action string) any {
	switch action {
	case "check":
		if p.configValue(s, "captcha_enabled") == "true" {
			return 1
		}
		return 0
	case "generate":
		kind := p.configValue(s, "captcha_type")
		if kind == "" || kind == "RANDOM" {
			kind = []string{"SLIDER", "WORD_IMAGE_CLICK", "ROTATE", "CONCAT"}[randomInt(4)]
		}
		return rawJSON{p.captcha.generate(kind)}
	case "verify":
		ok := p.captcha.verify(str(b["id"]), obj(b["data"]))
		if ok {
			return rawJSON{M{"code": 200, "msg": "success", "data": M{"validToken": b["id"]}}}
		}
		return rawJSON{M{"code": 4001, "msg": "验证码校验失败", "data": nil}}
	}
	panic("unknown captcha action")
}
func (c *captchas) generate(kind string) M {
	bg := captchaBackground()
	var template image.Image
	data := M{}
	ch := challenge{Kind: kind, Expiry: now() + 120000}
	tw, th := 60, 180
	switch kind {
	case "SLIDER":
		x, y := 65+randomInt(175), 25+randomInt(90)
		ch.X = float64(x)
		piece := image.NewNRGBA(image.Rect(0, 0, 60, 180))
		for py := 0; py < 50; py++ {
			for px := 0; px < 50; px++ {
				if (px > 4 && px < 46 && py > 4 && py < 46) || math.Hypot(float64(px-25), float64(py-5)) < 8 {
					piece.Set(px, y+py, bg.At(x+px, y+py))
					r, g, b, _ := bg.At(x+px, y+py).RGBA()
					bg.Set(x+px, y+py, color.RGBA{uint8(r >> 9), uint8(g >> 9), uint8(b >> 9), 255})
				}
			}
		}
		template = piece
	case "ROTATE":
		angle := float64(40 + randomInt(280))
		ch.X = 360 - angle
		tw, th = 180, 180
		piece := image.NewNRGBA(image.Rect(0, 0, tw, th))
		rad := angle * math.Pi / 180
		for y := 0; y < th; y++ {
			for x := 0; x < tw; x++ {
				dx, dy := float64(x-90), float64(y-90)
				if dx*dx+dy*dy <= 90*90 {
					sx := int(math.Cos(rad)*dx+math.Sin(rad)*dy) + 150
					sy := int(-math.Sin(rad)*dx+math.Cos(rad)*dy) + 90
					piece.Set(x, y, bg.At(sx, sy))
				}
			}
		}
		for y := 0; y < 180; y++ {
			for x := 60; x < 240; x++ {
				if (x-150)*(x-150)+(y-90)*(y-90) < 90*90 {
					bg.Set(x, y, color.RGBA{100, 100, 100, 255})
				}
			}
		}
		template = piece
	case "CONCAT":
		offset, split := 65+randomInt(170), 60+randomInt(60)
		ch.X = float64(offset)
		copyBG := image.NewRGBA(bg.Bounds())
		draw.Draw(copyBG, bg.Bounds(), bg, image.Point{}, draw.Src)
		for y := 0; y < 180-split; y++ {
			for x := 0; x < 300; x++ {
				bg.Set(x, y, copyBG.At((x+offset)%300, y))
			}
		}
		data["randomY"] = split
		template = image.NewNRGBA(image.Rect(0, 0, 1, 1))
		tw, th = 1, 1
	case "WORD_IMAGE_CLICK":
		words := []rune("春夏秋冬山水风云天地日月星海花鸟")
		used := map[rune]bool{}
		slots := []int{0, 1, 2, 3}
		prompt := image.NewRGBA(image.Rect(0, 0, 160, 40))
		draw.Draw(prompt, prompt.Bounds(), image.NewUniform(color.White), image.Point{}, draw.Src)
		for i := 0; i < 4; i++ {
			var word rune
			for {
				word = words[randomInt(len(words))]
				if !used[word] {
					used[word] = true
					break
				}
			}
			slotIndex := randomInt(len(slots))
			slot := slots[slotIndex]
			slots = append(slots[:slotIndex], slots[slotIndex+1:]...)
			x := 20 + (slot%2)*145 + randomInt(70)
			y := 40 + (slot/2)*75 + randomInt(25)
			drawWord(bg, string(word), x, y, 30)
			drawWord(prompt, string(word), i*40+3, 32, 28)
			ch.Points = append(ch.Points, image.Pt(x+15, y-15))
		}
		template = prompt
		tw, th = 160, 40
	default:
		fail("不支持的验证码类型")
	}
	id := randomHex(16)
	c.expire(now())
	c.mu.Lock()
	if len(c.items) >= 4096 {
		c.mu.Unlock()
		statusError(429, "captcha capacity exceeded")
	}
	c.items[id] = ch
	c.mu.Unlock()
	return M{"id": id, "captcha": M{"type": kind, "backgroundImage": pngURL(bg), "templateImage": pngURL(template), "backgroundImageWidth": 300, "backgroundImageHeight": 180, "templateImageWidth": tw, "templateImageHeight": th, "backgroundImageTag": "default", "templateImageTag": "default", "data": data}}
}
func (c *captchas) verify(id string, data M) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch, ok := c.items[id]
	delete(c.items, id)
	if !ok || ch.Expiry <= now() || ch.Verified {
		return false
	}
	tracks := arr(data["trackList"])
	if len(tracks) < 2 || len(tracks) > 4096 {
		return false
	}
	width, height := num(data["bgImageWidth"]), num(data["bgImageHeight"])
	if width < 1 || width > 4096 || height < 1 || height > 4096 {
		return false
	}
	lastTime := int64(-1)
	for _, v := range tracks {
		t := num(obj(v)["t"])
		if t < lastTime || t > 120000 {
			return false
		}
		lastTime = t
	}
	if lastTime < 100 {
		return false
	}
	valid := false
	if ch.Kind == "WORD_IMAGE_CLICK" {
		clicks := []M{}
		for _, v := range tracks {
			m := obj(v)
			if str(m["type"]) == "click" {
				clicks = append(clicks, m)
			}
		}
		if len(clicks) == len(ch.Points) {
			valid = true
			for i, point := range ch.Points {
				x := float64(num(clicks[i]["x"])) * 300 / float64(width)
				y := float64(num(clicks[i]["y"])) * 180 / float64(height)
				if math.Hypot(x-float64(point.X), y-float64(point.Y)) > 24 {
					valid = false
				}
			}
		}
	} else {
		last := obj(tracks[len(tracks)-1])
		if str(last["type"]) != "up" {
			return false
		}
		x := float64(num(last["x"]))
		scale := 300.0
		tolerance := 6.0
		if ch.Kind == "ROTATE" {
			scale = 360
			tolerance = 6
		}
		value := x * scale / float64(width)
		valid = math.Abs(value-ch.X) <= tolerance
	}
	if valid {
		ch.Verified = true
		ch.Expiry = time.Now().Add(120 * time.Second).UnixMilli()
		c.items[id] = ch
	}
	return valid
}

var captchaFontOnce sync.Once
var captchaParsedFont *opentype.Font
var captchaFontError error

func cachedCaptchaFont() *opentype.Font {
	captchaFontOnce.Do(func() {
		data, e := captchaAssets.ReadFile("captcha-assets/font.ttc")
		if e != nil {
			captchaFontError = e
			return
		}
		fonts, e := opentype.ParseCollection(data)
		if e != nil {
			captchaFontError = e
			return
		}
		captchaParsedFont, captchaFontError = fonts.Font(0)
	})
	must(captchaFontError)
	return captchaParsedFont
}
