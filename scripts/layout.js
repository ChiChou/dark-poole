document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('article.post.full img').forEach(img => {
    if (img.naturalWidth < 640) return
    const parent = img.parentElement
    if (parent.tagName === 'a') return
    const src = img.getAttribute('src')
    const a = document.createElement('a')
    a.setAttribute('href', src)
    a.setAttribute('target', '_blank')
    parent.insertBefore(a, img)
    parent.removeChild(img)
    a.appendChild(img)
    a.style.display = 'block'
    img.style.margin = 'auto'
  })

  document.querySelectorAll('code').forEach(code => {
    if (code.clientWidth > code.parentElement.clientWidth) {
      console.log(code)
      code.parentElement.style.overflowWrap = 'break-word'
    }
  })

  const main = document.querySelector('main')
  if (!main) return

  function resetVideos() {
    const width = main.clientWidth
    document.querySelectorAll('iframe[src^="https://www.youtube.com"]').forEach(video => {
      video.setAttribute('width', width)
      video.setAttribute('height', width * 9 / 16)
    })
  }

  window.addEventListener('resize', resetVideos)
  resetVideos()
})