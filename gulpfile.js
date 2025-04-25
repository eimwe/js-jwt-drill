const sass = require("gulp-sass")(require("sass"));
const browserSync = require("browser-sync").create();
const terser = require("gulp-terser");
const cleanCss = require("gulp-clean-css");
const createSourcemap = require("gulp-sourcemaps");
const deleteSourcemap = require("gulp-remove-sourcemaps");
const del = require("del");
const { src, series, parallel, dest, watch } = require("gulp");
const markupPath = "src/*.html";
const assetsPath = "src/assets/**/*";
const stylesPath = "src/styles/**/*.scss";
const scriptsPath = "src/scripts/**/*.js";

function copyHtml() {
  return src(markupPath).pipe(dest("dist"));
}

function copyAssets() {
  return src(assetsPath).pipe(dest("dist/assets"));
}

function copyScripts() {
  return src(scriptsPath).pipe(dest("dist/scripts"));
}

function compileStyles() {
  return src(stylesPath)
    .pipe(createSourcemap.init())
    .pipe(sass().on("error", sass.logError))
    .pipe(createSourcemap.write())
    .pipe(dest("dist/styles"))
    .pipe(browserSync.stream());
}

function serveUpdates() {
  browserSync.init({
    server: {
      baseDir: "./dist/",
    },
    middleware: function (req, res, next) {
      res.setHeader("Service-Worker-Allowed", "/");
      next();
    },
  });

  watch(stylesPath, compileStyles);
  watch(assetsPath, copyAssets);
  watch(markupPath, copyHtml).on("change", browserSync.reload);
  watch(scriptsPath, copyScripts).on("change", browserSync.reload);
}

function cleanDir() {
  return del(["dist/**"], { force: true });
}

function minifyStyles() {
  return src("dist/styles/*.css")
    .pipe(cleanCss())
    .pipe(deleteSourcemap())
    .pipe(dest("dist/styles"));
}

function minifyScripts() {
  return src("dist/scripts/*.js").pipe(terser()).pipe(dest("dist/scripts"));
}

exports.dev = series(
  cleanDir,
  parallel(copyHtml, copyScripts, copyAssets, compileStyles),
  serveUpdates
);

exports.prod = parallel(minifyStyles, minifyScripts);
