const SYMBOLS = ['🦊', '🦉', '🐙', '🌵', '🍄', '🔮', '🚀', '⚡'];
const BEST_KEY = 'tile-flip.best';
const THEME_KEY = 'tile-flip.theme';
const FLIP_BACK_MS = 650;

const boardEl = document.getElementById('board');
const movesEl = document.getElementById('moves');
const timeEl = document.getElementById('time');
const bestEl = document.getElementById('best');
const hintEl = document.getElementById('hint');
const themeEl = document.getElementById('theme');
const overlayEl = document.getElementById('overlay');
const winTextEl = document.getElementById('winText');

let firstTile = null;
let locked = false;
let moves = 0;
let matched = 0;
let startedAt = 0;
let tickerId = null;

function shuffle(items) {
  const deck = items.slice();
  for (let i = deck.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [deck[i], deck[j]] = [deck[j], deck[i]];
  }
  return deck;
}

function formatTime(ms) {
  const total = Math.floor(ms / 1000);
  return `${Math.floor(total / 60)}:${String(total % 60).padStart(2, '0')}`;
}

function readBest() {
  const best = Number(localStorage.getItem(BEST_KEY));
  bestEl.textContent = best > 0 ? String(best) : '-';
  return best > 0 ? best : Infinity;
}

function startTimer() {
  if (tickerId) return;
  startedAt = Date.now();
  tickerId = setInterval(() => {
    timeEl.textContent = formatTime(Date.now() - startedAt);
  }, 250);
}

function stopTimer() {
  clearInterval(tickerId);
  tickerId = null;
}

function isFaceUp(tile) {
  return tile.classList.contains('flipped') || tile.classList.contains('matched');
}

function flip(tile) {
  if (locked || isFaceUp(tile)) return;

  startTimer();
  tile.classList.add('flipped');
  tile.setAttribute('aria-label', tile.dataset.symbol);

  if (!firstTile) {
    firstTile = tile;
    return;
  }

  const second = tile;
  moves += 1;
  movesEl.textContent = String(moves);

  if (firstTile.dataset.symbol === second.dataset.symbol) {
    firstTile.classList.add('matched');
    second.classList.add('matched');
    firstTile.setAttribute('aria-label', `${firstTile.dataset.symbol} matched`);
    second.setAttribute('aria-label', `${second.dataset.symbol} matched`);
    firstTile = null;
    matched += 1;
    if (matched === SYMBOLS.length) win();
    return;
  }

  locked = true;
  const previous = firstTile;
  firstTile = null;
  setTimeout(() => {
    previous.classList.remove('flipped');
    second.classList.remove('flipped');
    previous.setAttribute('aria-label', 'Hidden tile');
    second.setAttribute('aria-label', 'Hidden tile');
    locked = false;
  }, FLIP_BACK_MS);
}

function win() {
  const elapsed = Date.now() - startedAt;
  stopTimer();

  const best = readBest();
  if (moves < best) {
    localStorage.setItem(BEST_KEY, String(moves));
    readBest();
    winTextEl.textContent = `New best: ${moves} moves in ${formatTime(elapsed)}.`;
  } else {
    winTextEl.textContent = `${moves} moves in ${formatTime(elapsed)}.`;
  }

  hintEl.textContent = 'Solved. Nicely done.';
  setTimeout(() => { overlayEl.hidden = false; }, 450);
}

function buildTile(symbol) {
  const tile = document.createElement('button');
  tile.type = 'button';
  tile.className = 'tile';
  tile.dataset.symbol = symbol;
  tile.setAttribute('aria-label', 'Hidden tile');
  tile.innerHTML = '<span class="tile-inner"><span class="face face-back">?</span><span class="face face-front"></span></span>';
  tile.querySelector('.face-front').textContent = symbol;
  tile.addEventListener('click', () => flip(tile));
  return tile;
}

function newGame() {
  overlayEl.hidden = true;
  stopTimer();
  firstTile = null;
  locked = false;
  moves = 0;
  matched = 0;
  startedAt = 0;
  movesEl.textContent = '0';
  timeEl.textContent = '0:00';
  hintEl.textContent = 'Flip two tiles to find a matching pair.';
  readBest();

  boardEl.replaceChildren(...shuffle([...SYMBOLS, ...SYMBOLS]).map(buildTile));
}

function currentTheme() {
  return document.documentElement.dataset.theme === 'dark' ? 'dark' : 'light';
}

function applyTheme(theme) {
  const dark = theme === 'dark';
  document.documentElement.dataset.theme = theme;
  themeEl.textContent = dark ? 'Light' : 'Dark';
  themeEl.setAttribute('aria-pressed', String(dark));
  themeEl.setAttribute('aria-label', dark ? 'Switch to light theme' : 'Switch to dark theme');
}

themeEl.addEventListener('click', () => {
  const next = currentTheme() === 'dark' ? 'light' : 'dark';
  localStorage.setItem(THEME_KEY, next);
  applyTheme(next);
});

applyTheme(currentTheme());

document.getElementById('newGame').addEventListener('click', newGame);
document.getElementById('playAgain').addEventListener('click', newGame);

newGame();
