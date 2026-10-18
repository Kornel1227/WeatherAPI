require('dotenv').config();
const express = require('express');
var cors =require('cors');
const mysql = require('mysql');
var sha1 = require('sha1');
const { get } = require('node:http');
const app = express();
const port = process.env.APP_PORT;
const pwdRegExp = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$/;

var pool = mysql.createPool({
  connectionLimit:      process.env.DB_CONN_LIMIT, 
  multipleStatements:   process.env.DB_MULTI_QUERY,
  host:                 process.env.DB_HOST,
  user:                 process.env.DB_USER,
  port:                 process.env.DB_PORT,
  password:             process.env.DB_PASS,
  database:             process.env.DB_NAME,
  timezone:             process.env.DB_TIMEZONE
});

app.use(express.json());
app.use(cors()); // ez kell, hogy a frontendrol jon a request
app.use(express.urlencoded({ extended: true })); // ez kell, hogy a req.body mukodjon


//GUEST ENDPOINTS:
//-----------------------------
//HOME PAGE
app.get('/', (req, res) =>{
    res.send('Welcome to the Weather API!');
})

//GET weather 
app.get('/weather', (req, res) => {
    pool.query('SELECT * FROM weather_forecasts ORDER BY date ASC, location ASC', (error, results) => {
        if(error){
            return res.status(500).json({error: 'Database query error'});
        }

        return res.status(200).json(results);
    });
});


//POST register 
app.post('/register', (req, res) => {
    const { name, email, password, confirm } = req.body;

    if(!name || !email || !password || !confirm) {
        return res.status(400).json({ error: 'All fields are required' });
    }
    if(password !== confirm) {
        return res.status(400).json({ error: 'Passwords do not match' });
    }

    if(!password.match(pwdRegExp)){
        return res.status(400).json({error: 'This is weak password!'})
    }
    

    pool.query('SELECT * FROM users WHERE email = ?', [email], (error, results) => {
        if (error){
            return res.status(500).json({ error: 'Database insert error', error });
        }
        if (results.length > 0) {
            return res.status(400).json({ error: 'This e-mail already exists' });
        }

        pool.query('INSERT INTO users (name,email, password, role) VALUES (?, ?, SHA1(?), "user")', [name, email, password], (error, results) => {
            if(error) {
                return res.status(500).json({ error: 'Database error', error });
            }
            return res.status(200).json({ message: 'User registered successfully' });
        });
    });
});


//POST login 
app.post('/login', (req, res) => {
    const { email, password} = req.body;

    if(!email || !password) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    pool.query('SELECT * FROM users WHERE email = ? AND password = SHA1(?)', [email, password], (error, results) => {
        if (error){
            return res.status(500).json({ error: 'Database query error', error });
        }

        if (results.length == 0){
            return res.status(400).json({ error: 'Invalid credentials!' });
        }

        if(results[0].is_active == 0){
            return res.status(400).json({error: 'This user is banned by admin'})
        }

        const loggedUser = {
            ID: results[0].ID,
            name: results[0].name,
            email: results[0].email,
            role: results[0].role
        }
        
        pool.query('UPDATE users SET last_login= CURRENT_TIMESTAMP, login_count = login_count + 1 WHERE ID=?', [loggedUser.ID], (error, results)=> {
            if (error){
                return res.status(500).json({ error: 'Database query error', error });
            }
            res.status(200).json({ message: 'Login successful', loggedUser});
        });


        
    });
})

//USERS ENDPOINTS:
//-----------------------------
//POST login
app.post('/users/login', (req, res) => {
    const { email, password} = req.body;

    if(!email || !password) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    pool.query('SELECT * FROM users WHERE email = ? AND password = SHA1(?)', [email, password], (error, results) => {
        if (error){
            return res.status(500).json({ error: 'Database query error', error });
        }

        if (results.length == 0){
            return res.status(400).json({ error: 'Invalid credentials!' });
        }

        if(results[0].is_active == 0){
            return res.status(400).json({error: 'This user is banned by admin'})
        }

        const loggedUser = {
            ID: results[0].ID,
            name: results[0].name,
            email: results[0].email,
            role: results[0].role
        }

        pool.query('UPDATE users SET last_login= CURRENT_TIMESTAMP, login_count = login_count + 1 WHERE ID=?', [loggedUser.ID], (error, results)=> {
            if (error){
                return res.status(500).json({ error: 'Database query error', error });
            }

            res.status(200).json({ message: 'Login successful', loggedUser});
        });


        
    });
})


//GET profile 
app.get('/users/:uid', (req, res) => {
    const uid = req.params.uid;

    if(!uid) {
        return res.status(400).json({error: 'Missing user ID'});
    }

    pool.query('SELECT * FROM users WHERE ID = ?', [uid], (error, results) => {
        if(error){
            return res.status(500).json({error: 'Database query error'});
        }

        if (results.length == 0){
            return res.status(400).json({error: 'User with this ID does not exist!'})
        }

        let user = {
            "name": results[0].name,
            "email": results[0].email,
            "role": results[0].role,
            "created_at": results[0].created_at,
        }

        return res.status(200).json({results : user});
    });
});


//PATCH profile 
app.patch('/users/:uid', (req, res ) => {
    const uid = req.params.uid;
    const { username, email, luid } = req.body;

    if(!uid || !username || !email || !luid){
        return res.status(400).json({ error: 'Missing required fields'})
    }

    if (uid != luid){
        return res.status(400).json({error : 'You not have permission to update this user!'});
    }

    pool.query('SELECT * FROM users WHERE ID=?',[uid], (error, results) => {
        if(error){
            return res.status(500).json({error: 'Database query error'});
        }

        if (results.length == 0){
            return res.status(400).json({error: 'User with this ID does not exist!'})
        }

        if(username == results[0].name && (email == results[0].email)){
            return res.status(200).json({message: 'No update occured!'})
        }

        pool.query('SELECT * FROM users WHERE email=? AND ID<>?', [email, uid], (error, results2) => {
            if(error){
                return res.status(500).json({error: 'Database query error'});
            }
            if(results2.length > 0){
                return res.status(400).json({error: 'This e-mail addres is already used!'})
            }

            pool.query('UPDATE users SET name=? , email=?, updated_at=CURRENT_TIMESTAMP WHERE ID=?', [username,email, uid], (error, results3) =>{
                if(error){
                    return res.status(500).json({error: 'Database query error'});
                }

                return res.status(200).json({ message: 'User updated succesfully!'})
            })
        })
    })

})


//POST passmod 
app.post('/users/:uid/passmod', (req,res) => {
    const {oldpass, newpass, confirm} = req.body;
    const uid = req.params.uid;

    if(!oldpass || !newpass || !confirm) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    if(newpass !== confirm) {
        return res.status(400).json({ error: 'New password and confirmation do not match' });
    }
    
    if(oldpass == newpass){
        return res.status(400).json({error: 'The new password equals with old password!'})
    }
  
    if(!newpass.match(pwdRegExp)){
        return res.status(400).json({error: 'This is weak password'})
    }

    pool.query('SELECT * FROM users WHERE ID = ?', [uid], (error, results) => {
        if(error){
            return res.status(500).json({error: 'Database query error'});
        }
        if (results.length == 0){
            return res.status(400).json({error: 'User with this ID does not exist!'})
        }

        const oldpassHash = sha1(oldpass);
        console.log('Old Password Hash:', oldpassHash);
        if(results[0].password != oldpassHash){
            return res.status(400).json({error: 'The old password is not correct!'})
        }

        pool.query('UPDATE users SET password = SHA1(?) WHERE ID = ?', [newpass, uid], (error, results) => {
            if(error){
                return res.status(500).json({error: 'Database update error'});
            }

            res.status(200).json({message: 'Password changed successfully!'});
        });
    });
});


//GET weather details
app.get('/weather/:id', (req, res) => {
    const id = req.params.id;

    if(!id){
        return res.status(400).json({error: 'Missing weather ID'});
    }

    pool.query('SELECT * FROM weather_forecasts WHERE ID=?', [id], (error, results) => {
        if(error){
            return res.status(500).json({error: 'Database query error'});
        }

        if(results.length == 0){
            return res.status(404).json({error: 'Weather forecast with this ID does not exist!'});
        }

        return res.status(200).json({results: results[0]});
    });
});

//ADMIN ENDPOINTS:
//-----------------------------
//GET all users 
app.post('/admin/users', (req, res) => {
    const luid = req.body.luid;

    if(!luid){
        return res.status(400).json({error: 'Missing required fields!'})
    }
    pool.query('SELECT *FROM users WHERE ID=?', [luid], (error, results1) => {
        if(error){
            return res.status(500).json({error: 'Database query error!'})
        }
        if(results1.lenght == 0){
            return res.status(400).json({error: 'User with this ID does not exist!'})
        }
        if(results1[0].role != 'admin'){
            return res.status(403).json({error: 'You not have permission to change this status'})
        }   
        pool.query('SELECT * FROM users', (error, results) => {
            if (error) {
                res.status(500).json({  error: 'Database server error '});
            } else {
                res.status(200).json(results);
            }
        });
    })
});


//POST weather 
app.post('/admin/weather', (req, res) => {
    const { date, location, temp_min, temp_max, weather_type,
        precipitation_probability, wind_speed, uv_index, luid } = req.body;

    if(!date || !location || temp_min === undefined || temp_max === undefined || !weather_type || !luid){
        return res.status(400).json({error: 'Missing required fields!'});
    }

    if(Number(temp_min) > Number(temp_max)){
        return res.status(400).json({error: 'Minimum temperature cannot be greater than maximum temperature!'});
    }

    pool.query('SELECT * FROM users WHERE ID=?', [luid], (error, results1) => {
        if(error){
            return res.status(500).json({error: 'Database query error!'});
        }

        if(results1.length == 0){
            return res.status(400).json({error: 'User with this ID does not exist!'});
        }

        if(results1[0].role != 'admin'){
            return res.status(403).json({error: 'You do not have permission to add weather data!'});
        }

        pool.query(
            `INSERT INTO weather_forecasts
            (date, location, temp_min, temp_max, weather_type, precipitation_probability, wind_speed, uv_index)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                date,
                location,
                temp_min,
                temp_max,
                weather_type,
                precipitation_probability === undefined ? 0 : precipitation_probability,
                wind_speed === undefined ? 0 : wind_speed,
                uv_index === undefined || uv_index === '' ? null : uv_index
            ],
            (error, results) => {
                if(error){
                    return res.status(500).json({error: 'Database insert error'});
                }

                return res.status(200).json({message: 'Weather data added successfully!', ID: results.insertId});
            }
        );
    });
});

//PATCH weather 
app.patch('/admin/weather/:id', (req, res) => {
    const id = req.params.id;
    const { date, location, temp_min, temp_max, weather_type,
        precipitation_probability, wind_speed, uv_index, luid } = req.body;

    if(!id || !date || !location || temp_min === undefined || temp_max === undefined || !weather_type || !luid){
        return res.status(400).json({error: 'Missing required fields!'});
    }

    if(Number(temp_min) > Number(temp_max)){
        return res.status(400).json({error: 'Minimum temperature cannot be greater than maximum temperature!'});
    }

    pool.query('SELECT * FROM users WHERE ID=?', [luid], (error, results1) => {
        if(error){
            return res.status(500).json({error: 'Database query error!'});
        }

        if(results1.length == 0){
            return res.status(400).json({error: 'User with this ID does not exist!'});
        }

        if(results1[0].role != 'admin'){
            return res.status(403).json({error: 'You do not have permission to edit weather data!'});
        }

        pool.query('SELECT * FROM weather_forecasts WHERE ID=?', [id], (error, results1) => {
            if(error){
                return res.status(500).json({error: 'Database query error!'});
            }

            if(results1.length == 0){
                return res.status(404).json({error: 'Weather forecast with this ID does not exist!'});
            }

            pool.query(
                `UPDATE weather_forecasts
                SET date=?, location=?, temp_min=?, temp_max=?, weather_type=?,
                    precipitation_probability=?, wind_speed=?, uv_index=?
                WHERE ID=?`,
                [
                    date,
                    location,
                    temp_min,
                    temp_max,
                    weather_type,
                    precipitation_probability === undefined ? 0 : precipitation_probability,
                    wind_speed === undefined ? 0 : wind_speed,
                    uv_index === undefined || uv_index === '' ? null : uv_index,
                    id
                ],
                (error, results) => {
                    if(error){
                        return res.status(500).json({error: 'Database update error!'});
                    }

                    return res.status(200).json({message: 'Weather data updated successfully!'});
                }
            );
        });
    });
});

//DELETE weather 
app.delete('/admin/weather/:id', (req, res) => {
    const id = req.params.id;
    const { luid } = req.body;

    if(!id || !luid){
        return res.status(400).json({error: 'Missing required fields!'});
    }

    pool.query('SELECT * FROM users WHERE ID=?', [luid], (error, results1) => {
        if(error){
            return res.status(500).json({error: 'Database query error!'});
        }

        if(results1.length == 0){
            return res.status(400).json({error: 'User with this ID does not exist!'});
        }

        if(results1[0].role != 'admin'){
            return res.status(403).json({error: 'You do not have permission to delete weather data!'});
        }

        pool.query('SELECT * FROM weather_forecasts WHERE ID=?', [id], (error, results1) => {
            if(error){
                return res.status(500).json({error: 'Database query error!'});
            }

            if(results1.length == 0){
                return res.status(404).json({error: 'Weather forecast with this ID does not exist!'});
            }

            pool.query('DELETE FROM weather_forecasts WHERE ID=?', [id], (error, results) => {
                if(error){
                    return res.status(500).json({error: 'Database delete error!'});
                }

                return res.status(200).json({message: 'Weather data deleted successfully!'});
            });
        });
    });
});

//DENY user
app.patch('/admin/status', (req, res) => {
    const { uid, luid } = req.body;

    if(!uid || !luid){
        return req.status(400).json({error: 'Missing required fields!'});
    }

    pool.query('SELECT * FROM users WHERE ID=?', [luid], (error, results1) => {
        if(error){
            return res.status(500).json({error: 'Database query error!'})
        }
        if(results1.lenght == 0){
            return res.status(400).json({error: 'User with this ID does not exist!'})
        }
        if(results1[0].role != 'admin'){
            return res.status(400).json({error: 'You not have permission to change this status'})
        }
        pool.query('SELECT * FROM users WHERE ID=?', [uid], (error, results) => {
        if(error){
            return res.status(500).json({error: 'Database query error!'})
        }
        if(results.length == 0){
            return res.status(400).json({error: 'User with this ID does not exist!'})
        }
        
        pool.query('UPDATE users SET is_active = not is_active WHERE ID=?', [uid], (error,results2) => {
            if(error){
                return res.status(500).json({error: 'Database query error!'})
            }
            return res.status(200).json({error: 'User status changed!'})
        })
    })
    })
})
 

app.listen(port, () => {
    console.log(`WeatherAPI running on port ${port}`);
});