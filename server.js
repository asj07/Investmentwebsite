const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const querystring = require('querystring');

const DATA_DIR = path.join(__dirname, 'data');
const VIEW_DIR = path.join(__dirname, 'views');
const PUBLIC_DIR = path.join(__dirname, 'public');

const sessions = {};

function load(file) {
  return JSON.parse(fs.readFileSync(path.join(DATA_DIR, file), 'utf-8'));
}

function save(file, data) {
  fs.writeFileSync(path.join(DATA_DIR, file), JSON.stringify(data, null, 2));
}

function hashPassword(pw) {
  return crypto.createHash('sha256').update(pw).digest('hex');
}

function parseCookies(req) {
  const header = req.headers['cookie'];
  const cookies = {};
  if (header) {
    header.split(';').forEach(pair => {
      const [k, v] = pair.trim().split('=');
      cookies[k] = v;
    });
  }
  return cookies;
}

function getUser(req) {
  const cookies = parseCookies(req);
  const sid = cookies.sessionId;
  if (sid && sessions[sid]) {
    const users = load('users.json');
    return users.find(u => u.id === sessions[sid]);
  }
  return null;
}

function render(template, params={}) {
  let html = fs.readFileSync(path.join(VIEW_DIR, template), 'utf-8');
  for (const [k,v] of Object.entries(params)) {
    const regex = new RegExp('{{\\s*'+k+'\\s*}}', 'g');
    html = html.replace(regex, v);
  }
  return html;
}

function parseBody(req, callback) {
  let body = '';
  req.on('data', chunk => body += chunk.toString());
  req.on('end', () => {
    callback(querystring.parse(body));
  });
}

function send(res, status, body, headers={}) {
  res.writeHead(status, headers);
  res.end(body);
}

function serveStatic(req, res) {
  const filePath = path.join(PUBLIC_DIR, req.url.replace('/public/', ''));
  if (fs.existsSync(filePath)) {
    const stream = fs.createReadStream(filePath);
    stream.on('open', () => {
      res.writeHead(200);
      stream.pipe(res);
    });
    stream.on('error', () => send(res, 500, 'Error'));
  } else {
    send(res, 404, 'Not found');
  }
}

function requireAuth(req, res, role) {
  const user = getUser(req);
  if (!user) {
    send(res, 302, '', { 'Location': '/login' });
    return null;
  }
  if (role && user.role !== role) {
    send(res, 403, 'Forbidden');
    return null;
  }
  return user;
}

function handleHome(req, res, user) {
  const content = user ? `<p>Welcome ${user.username}! Go to <a href='/dashboard'>dashboard</a> or <a href='/logout'>logout</a>.</p>` : `<p><a href='/login'>Login</a> or <a href='/register'>Register</a></p>`;
  const html = render('index.html', { content });
  send(res, 200, html, { 'Content-Type': 'text/html' });
}

function handleRegister(req, res) {
  if (req.method === 'GET') {
    const html = render('register.html', { message: '' });
    send(res, 200, html, { 'Content-Type': 'text/html' });
  } else if (req.method === 'POST') {
    parseBody(req, body => {
      const users = load('users.json');
      if (users.find(u => u.username === body.username)) {
        const html = render('register.html', { message: 'Username exists' });
        send(res, 200, html, { 'Content-Type': 'text/html' });
        return;
      }
      const id = users.length ? Math.max(...users.map(u => u.id)) + 1 : 1;
      users.push({ id, username: body.username, password: hashPassword(body.password), role: 'customer' });
      save('users.json', users);
      send(res, 302, '', { 'Location': '/login' });
    });
  }
}

function handleLogin(req, res) {
  if (req.method === 'GET') {
    const html = render('login.html', { message: '' });
    send(res, 200, html, { 'Content-Type': 'text/html' });
  } else if (req.method === 'POST') {
    parseBody(req, body => {
      const users = load('users.json');
      const user = users.find(u => u.username === body.username && u.password === hashPassword(body.password));
      if (user) {
        const sid = crypto.randomBytes(16).toString('hex');
        sessions[sid] = user.id;
        send(res, 302, '', { 'Set-Cookie': `sessionId=${sid}; HttpOnly`, 'Location': '/dashboard' });
      } else {
        const html = render('login.html', { message: 'Invalid credentials' });
        send(res, 200, html, { 'Content-Type': 'text/html' });
      }
    });
  }
}

function handleLogout(req, res) {
  const cookies = parseCookies(req);
  const sid = cookies.sessionId;
  if (sid) delete sessions[sid];
  send(res, 302, '', { 'Set-Cookie': 'sessionId=; Max-Age=0', 'Location': '/' });
}

function handleDashboard(req, res, user) {
  if (user.role === 'admin') {
    const plans = load('plans.json');
    const users = load('users.json');
    const investments = load('investments.json');
    const totalFunds = investments.reduce((sum, i) => sum + Number(i.amount), 0);
    const html = render('admin.html', {
      plans: plans.map(p => `<li>${p.name} - ${p.description}</li>`).join(''),
      usercount: users.length,
      investcount: investments.length,
      funds: totalFunds
    });
    send(res, 200, html, { 'Content-Type': 'text/html' });
  } else {
    const plans = load('plans.json');
    const investments = load('investments.json').filter(i => i.userId === user.id);
    const html = render('customer.html', {
      plans: plans.map(p => `<li>${p.name} - ${p.description} <form method='POST' action='/invest'><input type='hidden' name='planId' value='${p.id}'/><input name='amount' type='number' min='1' required/><button type='submit'>Invest</button></form></li>`).join(''),
      portfolio: investments.map(i => {
        const plan = plans.find(p => p.id === i.planId) || { name: 'Unknown' };
        return `<li>${plan.name}: $${i.amount}</li>`;
      }).join('') || '<li>No investments</li>'
    });
    send(res, 200, html, { 'Content-Type': 'text/html' });
  }
}

function handleAddPlan(req, res, user) {
  if (req.method === 'POST') {
    parseBody(req, body => {
      const plans = load('plans.json');
      const id = plans.length ? Math.max(...plans.map(p => p.id)) + 1 : 1;
      plans.push({ id, name: body.name, description: body.description });
      save('plans.json', plans);
      send(res, 302, '', { 'Location': '/dashboard' });
    });
  } else {
    send(res, 405, 'Method Not Allowed');
  }
}

function handleInvest(req, res, user) {
  if (req.method === 'POST') {
    parseBody(req, body => {
      const investments = load('investments.json');
      const id = investments.length ? Math.max(...investments.map(i => i.id)) + 1 : 1;
      investments.push({ id, userId: user.id, planId: Number(body.planId), amount: Number(body.amount) });
      save('investments.json', investments);
      send(res, 302, '', { 'Location': '/dashboard' });
    });
  } else {
    send(res, 405, 'Method Not Allowed');
  }
}

function handleContact(req, res) {
  if (req.method === 'GET') {
    const html = render('contact.html', { message: '' });
    send(res, 200, html, { 'Content-Type': 'text/html' });
  } else if (req.method === 'POST') {
    parseBody(req, body => {
      const messages = load('messages.json');
      messages.push({ name: body.name, email: body.email, message: body.message });
      save('messages.json', messages);
      const html = render('contact.html', { message: 'Message received' });
      send(res, 200, html, { 'Content-Type': 'text/html' });
    });
  }
}

const server = http.createServer((req, res) => {
  const user = getUser(req);
  if (req.url.startsWith('/public/')) {
    serveStatic(req, res);
    return;
  }
  if (req.url === '/' && req.method === 'GET') return handleHome(req, res, user);
  if (req.url === '/register') return handleRegister(req, res);
  if (req.url === '/login') return handleLogin(req, res);
  if (req.url === '/logout' && req.method === 'GET') return handleLogout(req, res);
  if (req.url === '/dashboard') {
    const u = requireAuth(req, res);
    if (u) handleDashboard(req, res, u);
    return;
  }
  if (req.url === '/admin/addPlan') {
    const u = requireAuth(req, res, 'admin');
    if (u) handleAddPlan(req, res, u);
    return;
  }
  if (req.url === '/invest') {
    const u = requireAuth(req, res, 'customer');
    if (u) handleInvest(req, res, u);
    return;
  }
  if (req.url === '/contact') return handleContact(req, res);
  send(res, 404, 'Not found');
});

if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  server.listen(PORT, () => console.log('Server running on', PORT));
}

module.exports = server;
