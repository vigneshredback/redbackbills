/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './templates/**/*.html', // Adjust path to your Django templates
    './static/**/*.js',      // Adjust path to your static JS files
  ],
  theme: {
    extend: {
      colors:{
        'primary':'red',
        'secondary':'#ff5555'
      }
    },
  },
  plugins: [],
}
