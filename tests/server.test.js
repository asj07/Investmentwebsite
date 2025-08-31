const { test, beforeEach } = require('node:test');
const assert = require('node:assert');
const http = require('http');
const fs = require('fs');
const path = require('path');
const server = require('../server');

const DATA = path.join(__dirname, '..', 'data');
const initialUsers = `[{"id":1,"username":"admin","password":"713bfda78870bf9d1b261f565286f85e97ee614efe5f0faf7c34e7ca4f65baca","role":"admin"}]`;
const initialPlans = `[]`;
const initialInvestments = `[]`;
const initialMessages = `[]`;

beforeEach(() => {
  fs.writeFileSync(path.join(DATA, 'users.json'), initialUsers);
  fs.writeFileSync(path.join(DATA, 'plans.json'), initialPlans);
  fs.writeFileSync(path.join(DATA, 'investments.json'), initialInvestments);
  fs.writeFileSync(path.join(DATA, 'messages.json'), initialMessages);
});

function request(method, pathUrl, data, port, cookie) {
  return new Promise((resolve, reject) => {
    const options = { method, port, path: pathUrl, headers: { 'Content-Type': 'application/x-www-form-urlencoded' } };
    if (cookie) options.headers['Cookie'] = cookie;
    const req = http.request(options, res => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
    });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

test('registration, login, add plan and invest', async () => {
  await new Promise(resolve => server.listen(0, resolve));
  const port = server.address().port;

  // register user
  let res = await request('POST', '/register', 'username=alice&password=pass', port);
  assert.strictEqual(res.status, 302);
  const users = JSON.parse(fs.readFileSync(path.join(DATA, 'users.json')));
  assert.ok(users.find(u => u.username === 'alice'));

  // admin login and add plan
  res = await request('POST', '/login', 'username=admin&password=adminpass', port);
  const adminCookie = res.headers['set-cookie'][0].split(';')[0];
  res = await request('POST', '/admin/addPlan', 'name=Plan1&description=Test', port, adminCookie);
  assert.strictEqual(res.status, 302);
  const plans = JSON.parse(fs.readFileSync(path.join(DATA, 'plans.json')));
  assert.strictEqual(plans.length, 1);

  // user login and invest
  res = await request('POST', '/login', 'username=alice&password=pass', port);
  const userCookie = res.headers['set-cookie'][0].split(';')[0];
  res = await request('POST', '/invest', 'planId=1&amount=100', port, userCookie);
  assert.strictEqual(res.status, 302);
  const investments = JSON.parse(fs.readFileSync(path.join(DATA, 'investments.json')));
  assert.strictEqual(investments.length, 1);
  server.close();
});
