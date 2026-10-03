export default async function run(page, ui) {
  await page.setViewportSize({ width: 320, height: 800 })
  await page.waitForTimeout(1500)
  const out = await page.evaluate(() => {
    const main = document.querySelector('main')
    const vw = 320
    const bad = []
    main.querySelectorAll('*').forEach(el => {
      const r = el.getBoundingClientRect()
      if (r.right > vw + 1) {
        const cs = getComputedStyle(el)
        bad.push({
          tag: el.tagName,
          cls: (el.className || '').toString().slice(0, 80),
          text: (el.textContent || '').trim().slice(0, 35),
          w: Math.round(r.width),
          right: Math.round(r.right),
          minW: cs.minWidth, ws: cs.whiteSpace,
        })
      }
    })
    // keep only elements whose parent does NOT overflow -> the true culprit
    const culprits = bad.filter(b => {
      const el = [...main.querySelectorAll('*')].find(e => (e.className || '').toString().slice(0, 80) === b.cls && (e.textContent || '').trim().slice(0, 35) === b.text && Math.round(e.getBoundingClientRect().width) === b.w)
      if (!el || !el.parentElement) return false
      return el.parentElement.getBoundingClientRect().right <= vw + 1
    })
    return { vw, mainW: main.clientWidth, mainScrollW: main.scrollWidth, count: bad.length, culprits: culprits.slice(0, 8) }
  })
  return out
}