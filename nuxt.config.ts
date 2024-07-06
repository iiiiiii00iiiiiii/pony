export default defineNuxtConfig({
    devtools: { enabled: true },
    css: ['bootstrap/dist/css/bootstrap.min.css'],
    plugins: [{ src: '~/plugins/bootstrap.js', mode: 'client' }]
})