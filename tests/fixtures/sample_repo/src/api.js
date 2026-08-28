const express = require('express');
const child_process = require('child_process');

const app = express();

app.get('/api/v1/users', (req, res) => {
    res.json([{ id: 1, name: 'Alice' }]);
});

app.post('/api/v1/ping', (req, res) => {
    child_process.exec('ping -c 1 127.0.0.1', (err, stdout) => {
        res.send(stdout);
    });
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
