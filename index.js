const express = require('express');
const mysql = require('mysql');
const bodyParser = require('body-parser');
const cors = require('cors');
const multer = require('multer');
const xlsx = require('xlsx');
const fs = require('fs');
const uuid = require('uuid');
const sgMail = require('@sendgrid/mail');
const bcrypt = require('bcrypt');
const dayjs = require('dayjs');
const jwt = require('jsonwebtoken');
const moment = require('moment-timezone');


require('dotenv').config();

const app = express();
const port = process.env.PORT;
const jwtSecret = process.env.JWT_SECRET;

// Middleware
app.use(bodyParser.json());
app.use(cors());

// MySQL Connection local
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE
});

db.connect((err) => {
  if (err) {
    throw err;
  }
  console.log('MySQL connected...');
});


// Generate JWT token
function generateToken(user) {
  return jwt.sign({ id: user.id, username: user.username }, jwtSecret, { expiresIn: '8h' });
}

// Authentication Middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token == null) return res.sendStatus(401);

  jwt.verify(token, jwtSecret, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}


app.get('/api', (req, res) => {
  res.send('Hello dev!')
})

app.post('/api/register', authenticateToken, (req, res) => {
  const { username, email, fullname, role, password } = req.body;

  // Check if username or email already exists in the database
  const checkQuery = 'SELECT COUNT(*) AS count FROM users WHERE username = ? OR email = ?';
  db.query(checkQuery, [username, email], async (checkErr, checkResult) => {
    if (checkErr) {
      res.status(500).json({ error: checkErr.message });
    } else {
      const { count } = checkResult[0];
      if (count > 0) {
        res.status(400).json({ error: 'Username or email already exists.' });
      } else {
        try {
          // Generate a unique ID for the user
          const id = uuid.v4();

          // Hash the password
          const hashedPassword = await bcrypt.hash(password, 10); // 10 is the saltRounds

          // Insert the new user into the database
          const insertQuery = 'INSERT INTO users (id, username, email, fullname, role, password) VALUES (?, ?, ?, ?, ?, ?)';
          db.query(insertQuery, [id, username, email, fullname, role, hashedPassword], (insertErr, insertResult) => {
            if (insertErr) {
              res.status(500).json({ error: insertErr.message });
            } else {
              res.status(200).json({ message: 'User registered successfully!' });
            }
          });
        } catch (hashErr) {
          res.status(500).json({ error: hashErr.message });
        }
      }
    }
  });
});

// Login API
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  const sql = 'SELECT * FROM users WHERE username = ?'; // No need to check password here
  db.query(sql, [username], async (err, result) => {
    if (err) {
      res.status(500).json({ error: err.message });
    } else if (result.length === 0) {
      res.status(401).json({ message: 'Invalid username or password' });
    } else {
      // Compare the provided password with the hashed password from the database
      try {
        const match = await bcrypt.compare(password, result[0].password);
        if (match) {
          if (result[0].state !== 'active') {
            res.status(401).json({ message: 'User is not active' });
          } else {
            // Generate JWT token upon successful login
            const token = generateToken(result[0]);
            res.status(200).json({ message: 'Login successful!', user: result[0], token });
          }
        } else {
          res.status(401).json({ message: 'Invalid username or password' });
        }
      } catch (compareErr) {
        res.status(500).json({ error: compareErr.message });
      }
    }
  });
});

// Fetch table data API
app.get('/api/data', authenticateToken, (req, res) => {
  try {
    // Construct the base SQL query
    let sql = 'SELECT id, Name, Phone, Email, Website, status, DATE(date_added) AS date_added, emails_sent, Note, added_by, trash, deleted_by, niche, Result, priority, \`Social Media\`, Owner FROM Contacts';

    // Check if filterOption, status, date_added, added_by, date, or trash query parameters are provided
    const { filterOption, status, date_added, added_by, date, trash, priority } = req.query;
    let whereClause = '';

    // Apply filter based on filterOption
    if (filterOption) {
      let filterCondition = '';
      switch (filterOption) {
        case 'lastHour':
          filterCondition = `date_added >= NOW() - INTERVAL 1 HOUR`;
          break;
        case 'lastDay':
          filterCondition = `date_added >= NOW() - INTERVAL 1 DAY`;
          break;
        case 'lastWeek':
          filterCondition = `date_added >= NOW() - INTERVAL 1 WEEK`;
          break;
        case 'lastMonth':
          filterCondition = `date_added >= NOW() - INTERVAL 1 MONTH`;
          break;
        default:
          break;
      }

      if (filterCondition) {
        whereClause = `WHERE ${filterCondition}`;
      }
    }

    // Apply status filter
    if (status) {
      whereClause = whereClause ? `${whereClause} AND status = '${status}'` : `WHERE status = '${status}'`;
    }

    // Apply date_added filter
    if (date_added) {
      whereClause = whereClause ? `${whereClause} AND DATE(date_added) = '${date_added}'` : `WHERE DATE(date_added) = '${date_added}'`;
    }

    // Apply added_by filter
    if (added_by) {
      whereClause = whereClause ? `${whereClause} AND added_by = '${added_by}'` : `WHERE added_by = '${added_by}'`;
    }

    // Apply date filter
    if (date) {
      whereClause = whereClause ? `${whereClause} AND DATE(date_added) = '${date}'` : `WHERE DATE(date_added) = '${date}'`;
    }

    // Apply trash filter
    if (trash) {
      whereClause = whereClause ? `${whereClause} AND trash = '${trash}'` : `WHERE trash = '${trash}'`;
    }

    // Apply priority filter
    if (priority !== undefined) {
      whereClause = whereClause ? `${whereClause} AND priority = '${priority}'` : `WHERE priority = '${priority}'`;
    }

    // Append whereClause to the SQL query if it exists
    if (whereClause) {
      sql += ` ${whereClause}`;
    }

    // Execute the SQL query
    db.query(sql, (err, result) => {
      if (err) {
        console.error('Error fetching data:', err);
        return res.status(500).json({ error: 'Failed to fetch data' });
      }
      res.status(200).json(result);
    });
  } catch (error) {
    console.error('Error fetching data:', error);
    return res.status(500).json({ error: 'Failed to fetch data' });
  }
});


app.get('/api/users/status', authenticateToken, (req, res) => {
  const userId = req.query.id;

  // If the id parameter is provided, fetch the status of a single entity
  if (userId) {
    const sql = 'SELECT status FROM users WHERE id = ?';
    db.query(sql, [userId], (err, result) => {
      if (err) {
        console.error('Error fetching status:', err.message);
        res.status(500).json({ error: 'Error fetching status' });
      } else {
        if (result.length === 0) {
          res.status(404).json({ error: 'User not found' });
        } else {
          res.status(200).json({ id: userId, status: result[0].status });
        }
      }
    });
  } else {
    // If no id parameter is provided, fetch the status of all entities
    const sql = 'SELECT id, fullname, status FROM users';
    db.query(sql, (err, result) => {
      if (err) {
        console.error('Error fetching status:', err.message);
        res.status(500).json({ error: 'Error fetching status' });
      } else {
        const usersStatus = result.map(row => ({
          id: row.id,
          fullname: row.fullname,
          status: row.status
        }));
        res.status(200).json(usersStatus);
      }
    });
  }
});





// File upload configuration using multer
const upload = multer({ dest: 'uploads/' });

// API endpoint to handle file uploads and database insertion
app.post('/api/upload', authenticateToken, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const workbook = xlsx.readFile(req.file.path);
    const sheetName = workbook.SheetNames[0];
    const worksheet = workbook.Sheets[sheetName];
    let data = xlsx.utils.sheet_to_json(worksheet);

    console.log('Data from Excel:', data); // Log the data here

    if (data.length === 0) {
      return res.status(400).json({ error: 'No data found in the Excel file' });
    }

    // Retrieve niche from query parameters
    const niche = req.query.niche;

    let existingContacts = [];

    try {
      // Fetch existing contacts from the database
      const existingContactsResult = await db.query(`SELECT Email, Phone FROM Contacts`);
      existingContacts = existingContactsResult.rows;
    } catch (error) {
      console.error('Error fetching existing contacts:', error);
      // Handle the error when fetching existing contacts
      return res.status(500).json({ error: 'Error fetching existing contacts', details: error.message });
    }

    // Ensure that existingContacts is an array
    existingContacts = existingContacts || [];

    // Extract emails and phone numbers from existing contacts
    const existingEmails = existingContacts.map(contact => contact.Email);
    const existingPhones = existingContacts.map(contact => contact.Phone);

    // Filter out existing contacts based on email or phone number
    data = data.filter(item => {
      return !existingEmails.includes(item.Email) && !existingPhones.includes(item.Phone);
    });

    // Add "niche" property to each item in the filtered data array
    data = data.map(item => ({ 
      ...item, 
      id: uuid.v4(), 
      status: 'active', 
      added_by: req.query.added_by,
      niche: niche, // Include the retrieved niche
      Result: item.Result || 'Ongoing', // Add 'Ongoing' if Result is not provided
      Owner: item.Owner || '', // Include Owner, default to empty string if not provided
      'Social Media': item['Social Media'] && isUrl(item['Social Media']) ? item['Social Media'] : item['Social Media'] || '', // Handle Social Media as links separated by comma if it's a URL
      Location: item.Location || '', // Include Location, default to empty string if not provided
      Note: item.Note || '', // Include Note, default to empty string if not provided
      priority: 3 // Set priority to 3 for all contacts
    }));

    if (data.length === 0) {
      return res.status(400).json({ error: 'No new contacts to add' });
    }

    const placeholders = data.map(() => '(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').join(', ');
    const sql = `INSERT INTO Contacts (id, Name, Phone, Email, Website, status, added_by, niche, Result, Owner, \`Social Media\`, Location, Note, priority) VALUES ${placeholders}`;
    const values = data.flatMap(row => [row.id, row.Name, row.Phone, row.Email, row.Website, row.status, row.added_by, row.niche, row.Result, row.Owner, row['Social Media'], row.Location, row.Note, row.priority]);

    console.log('Generated SQL:', sql); // Log the SQL query here
    console.log('Values:', values);

    db.query(sql, values, (err, result) => {
      if (err) {
        console.error('Error inserting data into database:', err.message);
        return res.status(500).json({ error: 'Error inserting data into database', details: err.message });
      } else {
        console.log('Data inserted successfully');
        return res.status(200).json({ message: 'Data inserted successfully' });
      }
    });
  } catch (error) {
    console.error('Error processing file upload:', error.message);
    return res.status(500).json({ error: 'Error processing file upload', details: error.message });
  } finally {
    if (req.file && req.file.path) {
      fs.unlinkSync(req.file.path);
    }
  }
});


function isUrl(s) {
  const regexp = /^(ftp|http|https):\/\/[^ "]+$/;
  return regexp.test(s);
}



app.post('/api/addContact', async (req, res) => {
  try {
    // Extract parameters from the request body
    const { Name, Phone, Email, Website, added_by, niche, Result } = req.body; // Removed 'Priority' parameter

    // Set priority to 3 by default
    const priority = 3;

    // Generate a unique ID for the contact
    const id = uuid.v4();

    // Insert the new contact into the database with added_by, niche, and priority information
    const result = await db.query('INSERT INTO Contacts (id, Name, Phone, Email, Website, status, added_by, niche, Result, priority) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', [id, Name, Phone, Email, Website, 'active', added_by, niche, Result, priority]);

    // Respond with success message
    res.json({ success: true, message: 'Contact added successfully' });
  } catch (error) {
    // If an error occurs, respond with an error message
    console.error('Error adding contact:', error);
    res.status(500).json({ success: false, message: 'Error adding contact' });
  }
});


app.put('/api/update', authenticateToken, (req, res) => {
  try {
    const { ids, Note, ...updates } = req.body;

    if (!ids || (Object.keys(updates).length === 0 && Note === undefined)) {
      return res.status(400).json({ error: 'IDs or updates are required' });
    }

    let sql = 'UPDATE Contacts SET ';
    const values = [];

    // Construct the SET clause dynamically based on the updates object
    Object.keys(updates).forEach((key, index) => {
      if (index > 0) {
        sql += ', ';
      }
      sql += `${key} = ?`;
      values.push(updates[key]);
    });

    // Add Note to SET clause if it's provided in the request body
    if (Note !== undefined) {
      if (Object.keys(updates).length > 0) {
        sql += ', ';
      }
      sql += `Note = ?`;
      values.push(Note);
    }

    sql += ' WHERE id IN (?)';
    values.push(ids);

    db.query(sql, values, (err, result) => {
      if (err) {
        console.error('Error updating entries:', err.message);
        return res.status(500).json({ error: 'Error updating entries', details: err.message });
      } else {
        console.log('Entries updated successfully');
        return res.status(200).json({ message: 'Entries updated successfully' });
      }
    });
  } catch (error) {
    console.error('Error updating entries:', error.message);
    return res.status(500).json({ error: 'Error updating entries', details: error.message });
  }
});






// Delete API
app.delete('/api/delete', authenticateToken, (req, res) => {
  const ids = req.body.ids;

  if (!ids || !Array.isArray(ids) || ids.length === 0) {
    return res.status(400).json({ error: 'Invalid IDs provided' });
  }

  const sql = 'DELETE FROM Contacts WHERE id IN (?)';
  db.query(sql, [ids], (err, result) => {
    if (err) {
      res.status(500).json({ error: err.message });
    } else {
      res.status(200).json({ message: 'Entries deleted successfully' });
    }
  });
});

// Initialize SendGrid with your API key
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

app.post('/api/send-email', authenticateToken, async (req, res) => {
  const { to, from, subject, message, footer } = req.body;

  try {
    // Check if all required fields are present
    if (!to || !from || !subject || !message) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Parse the 'to' field into an array if it's provided as a comma-separated string
    const toAddresses = Array.isArray(to) ? to : to.split(',').map(email => email.trim());

    // Iterate over each recipient and send individual emails
    for (const address of toAddresses) {
      const msg = {
        to: address,
        from,
        subject,
        html: `${message}<br><br>${footer}`
      };

      // Send the individual email
      await sgMail.send(msg);
    }

    // Save sent email to the database
    await saveSentEmailToDatabase(toAddresses, from, subject, message, footer);

    return res.status(200).json({ message: 'Emails sent successfully' });
  } catch (error) {
    console.error('Error sending emails:', error);

    // Handle specific errors
    if (error.response && error.response.body) {
      return res.status(error.response.statusCode).json({ error: 'Failed to send emails', details: error.response.body.errors });
    } else {
      return res.status(500).json({ error: 'Failed to send emails', details: error.message });
    }
  }
});



async function saveSentEmailToDatabase(to, from, subject, message, footer) {
  const sentAt = new Date().toISOString().slice(0, 19).replace('T', ' '); // Format the timestamp
  const emailId = uuid.v4(); // Generate UUID

  // Join the array of recipient email addresses with a comma
  const toEmailString = to.join(', ');

  const sql = 'INSERT INTO sent_emails (id, to_email, from_email, subject, message, footer, sent_at) VALUES (?, ?, ?, ?, ?, ?, ?)';
  const values = [emailId, toEmailString, from, subject, message, footer, sentAt];

  return new Promise((resolve, reject) => {
    db.query(sql, values, (err, result) => {
      if (err) {
        console.error('Error saving sent email to database:', err);
        reject(err);
      } else {
        console.log('Sent email saved to database successfully');
        resolve(result);
      }
    });
  });
}



app.put('/api/update-emails-sent', authenticateToken, (req, res) => {
  try {
    const { ids } = req.body;

    if (!ids || !Array.isArray(ids)) {
      return res.status(400).json({ error: 'IDs array is required' });
    }

    // Increment emails_sent by 1 for all specified IDs
    const sql = 'UPDATE Contacts SET emails_sent = emails_sent + 1 WHERE id IN (?)';
    const values = [ids];

    db.query(sql, values, (err, result) => {
      if (err) {
        console.error('Error updating emails_sent:', err.message);
        return res.status(500).json({ error: 'Error updating emails_sent', details: err.message });
      } else {
        console.log('Emails_sent updated successfully');
        return res.status(200).json({ message: 'Emails_sent updated successfully' });
      }
    });
  } catch (error) {
    console.error('Error updating emails_sent:', error.message);
    return res.status(500).json({ error: 'Error updating emails_sent', details: error.message });
  }
});


// Define an object to store user statuses
app.put('/api/users/updateStatus', authenticateToken, (req, res) => {
  const userId = req.query.id;
  const newData = req.body;

  if (!userId || !newData) {
    return res.status(400).json({ message: 'Missing required parameters.' });
  }

  // Construct the SET clause of the SQL query dynamically based on the provided parameters
  let setClause = '';
  const values = [];

  Object.keys(newData).forEach(key => {
    // Append each field to the SET clause
    setClause += `${key} = ?, `;
    values.push(newData[key]);
  });

  // Remove the trailing comma and space
  setClause = setClause.slice(0, -2);

  // Update the user in the database
  const sql = `UPDATE users SET ${setClause} WHERE id = ?`;
  const queryParams = [...values, userId];

  db.query(sql, queryParams, (err, result) => {
    if (err) {
      console.error('Error updating user:', err);
      return res.status(500).json({ message: 'Error updating user.' });
    }
    console.log('User updated successfully');
    return res.status(200).json({ message: 'User updated successfully.' });
  });
});



app.get('/api/users', authenticateToken, (req, res) => {
  // Query the database to get all users
  const sql = 'SELECT * FROM users';
  db.query(sql, (err, result) => {
    if (err) {
      console.error('Error fetching users:', err);
      res.status(500).json({ error: 'Error fetching users' });
    } else {
      // Return the fetched users as JSON response
      res.json(result);
    }
  });
});

// SendGrid event webhook notifications
app.post('/api/sendgrid/webhook', authenticateToken, (req, res) => {
  const events = req.body;

  if (!events || !Array.isArray(events)) {
    return res.status(400).json({ error: 'Invalid request body' });
  }

  try {
    events.forEach(event => {
      saveEventToDatabase(event);
    });
    res.status(200).send('OK');
  } catch (error) {
    console.error('Error processing webhook events:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Function to save event data to the database
function saveEventToDatabase(event) {
  const { email, timestamp, event: eventType, sg_event_id, sg_message_id, ...payload } = event;

  // Convert timestamp to MySQL datetime format
  const mysqlTimestamp = new Date(timestamp * 1000).toISOString().slice(0, 19).replace('T', ' ');

  const sql = 'INSERT INTO sendgrid_events (email, timestamp, event_type, sg_event_id, sg_message_id, payload) VALUES (?, ?, ?, ?, ?, ?)';
  const values = [email, mysqlTimestamp, eventType, sg_event_id, sg_message_id, JSON.stringify(payload)];

  db.query(sql, values, (err, result) => {
    if (err) {
      console.error('Error saving event to database:', err);
    } else {
      console.log('Event saved to database successfully');
    }
  });
}


app.get('/api/sendgrid-events', authenticateToken, (req, res) => {
  // Query the database to get all users
  const sql = 'SELECT * FROM sendgrid_events';
  db.query(sql, (err, result) => {
    if (err) {
      console.error('Error fetching users:', err);
      res.status(500).json({ error: 'Error fetching users' });
    } else {
      // Return the fetched users as JSON response
      res.json(result);
    }
  });
});

app.get('/api/get-sent-emails', authenticateToken, async (req, res) => {
  try {
    const { date } = req.query;
    let query = 'SELECT * FROM sent_emails';
    let params = [];

    // If date parameter is provided, filter emails by date
    if (date) {
      query += ' WHERE DATE(sent_at) >= ?';
      params.push(date);
    }

    db.query(query, params, (err, result) => {
      if (err) {
        console.error('Error fetching sent emails:', err);
        return res.status(500).json({ error: 'Failed to fetch sent emails' });
      }
      res.status(200).json(result);
    });
  } catch (error) {
    console.error('Error fetching sent emails:', error);
    return res.status(500).json({ error: 'Failed to fetch sent emails' });
  }
});

app.post('/api/make-event', authenticateToken, (req, res) => {
  const { name, start_date, end_date, client_name, client_email, priority, added_by } = req.body;
  const eventId = uuid.v4(); // Generate UUID for the event

  // Insert new event into database
  db.query('INSERT INTO events (id, name, start_date, end_date, client_name, client_email, priority, added_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
    [eventId, name, start_date, end_date, client_name, client_email, priority, added_by],
    (error, results) => {
      if (error) {
        console.error(error);
        res.status(500).send('Error inserting event into database');
      } else {
        res.status(200).send('Event added successfully');
      }
    });
});

app.get(['/api/get-event', '/api/get-event/:id'], authenticateToken, (req, res) => {
  const eventId = req.params.id; // Extract event ID from request params, if provided

  // Construct the SQL query based on whether an event ID is provided
  const sqlQuery = eventId ? `SELECT * FROM events WHERE id = '${eventId}'` : 'SELECT * FROM events';

  // Fetch events from the database
  db.query(sqlQuery, (error, results) => {
    if (error) {
      console.error(error);
      res.status(500).send('Error fetching events from database');
    } else {
      res.status(200).json(results);
    }
  });
});

app.delete('/api/delete-event/:id', authenticateToken, (req, res) => {
  const eventId = req.params.id; // Extract event ID from request params

  // Delete event from the database
  db.query('DELETE FROM events WHERE id = ?', eventId, (error, results) => {
    if (error) {
      console.error(error);
      res.status(500).send('Error deleting event from database');
    } else {
      res.status(200).send('Event deleted successfully');
    }
  });
});

app.put('/api/event-update/:id', authenticateToken, async (req, res) => {
  const eventId = req.params.id;
  const updatedEvent = req.body;

  // Convert start_date and end_date to EST timezone
  updatedEvent.start_date = moment(updatedEvent.start_date).tz('America/Toronto').format('YYYY-MM-DD HH:mm:ss');
  updatedEvent.end_date = moment(updatedEvent.end_date).tz('America/Toronto').format('YYYY-MM-DD HH:mm:ss');

  // Format added_time field
  updatedEvent.added_time = moment().tz('America/Toronto').format('YYYY-MM-DD HH:mm:ss');

  try {
    const sql = 'UPDATE events SET ? WHERE id = ?';
    db.query(sql, [updatedEvent, eventId], (err, result) => {
      if (err) {
        console.error('Error updating event:', err);
        res.status(500).json({ error: 'Internal server error' });
      } else {
        if (result.changedRows === 1) {
          res.status(200).json({ message: 'Event updated successfully' });
        } else {
          res.status(404).json({ error: 'Event not found' });
        }
      }
    });
  } catch (error) {
    console.error('Error updating event:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST endpoint to add a task to the to-do list
app.post('/api/todo-make', authenticateToken, (req, res) => {
  const { name, added_by } = req.body;
  const taskId = uuid.v4(); // Generate a unique UUID
  const sql = 'INSERT INTO TodoList (id, name, added_by) VALUES (?, ?, ?)';
  db.query(sql, [taskId, name, added_by], (err, result) => {
    if (err) {
      console.error('Error adding task:', err);
      res.status(500).send('Error adding task');
    } else {
      console.log('Task added successfully');
      res.status(201).send('Task added successfully');
    }
  });
});


app.get('/api/todo-get', authenticateToken, (req, res) => {
  const sql = 'SELECT id, name, completed, added_by FROM TodoList';
  db.query(sql, (err, results) => {
    if (err) {
      console.error('Error fetching tasks:', err);
      res.status(500).json({ message: 'Server error' });
      return;
    }
    console.log('Tasks:', results);
    res.json(results);
  });
});


// PUT endpoint to update a task
app.put('/api/todo/:id', authenticateToken, (req, res) => {
  const taskId = req.params.id;
  const { name, completed } = req.body;
  const sql = 'UPDATE TodoList SET name = ?, completed = ? WHERE id = ?';
  db.query(sql, [name, completed, taskId], (err, result) => {
    if (err) {
      console.error('Error updating task:', err);
      res.status(500).json({ message: 'Error updating task' }); // Return JSON error response
    } else {
      console.log('Task updated successfully');
      res.status(200).json({ message: 'Task updated successfully' }); // Return JSON success response
    }
  });
});


// DELETE endpoint to remove a task from the to-do list
app.delete('/api/todo/:id', authenticateToken, (req, res) => {
  const taskId = req.params.id;
  const sql = 'DELETE FROM TodoList WHERE id = ?';
  db.query(sql, [taskId], (err, result) => {
    if (err) {
      console.error('Error deleting task:', err);
      res.status(500).send('Error deleting task');
    } else {
      console.log('Task deleted successfully');
      res.status(200).send('Task deleted successfully');
    }
  });
});


app.get(['/api/casestudies-get', '/api/casestudy-get/:id'], (req, res) => {
  const { id } = req.params;

  if (id) {
      // Request is for a specific case study
      const sql = 'SELECT * FROM casestudies WHERE id = ?';
      db.query(sql, id, (err, result) => {
          if (err) {
              res.status(500).send('Error fetching data');
              throw err;
          }
          res.json(result[0]); // Assuming only one case study will match the given ID
      });
  } else {
      // Request is for all case studies
      const sql = 'SELECT * FROM casestudies';
      db.query(sql, (err, result) => {
          if (err) {
              res.status(500).send('Error fetching data');
              throw err;
          }
          res.json(result);
      });
  }
});


app.post('/api/casestudies-make', authenticateToken, (req, res) => {
  // Destructure required fields from the request body
  const { title, summary, client, banner, tags, challenge, solution, outcome, results, logo } = req.body;

  // Generate a unique ID for the case study
  const id = uuid.v4();

  // Prepare SQL query without logo field
  const sql = `
    INSERT INTO casestudies 
    (id, title, summary, client, banner, logo, tags, challenge, solution, outcome, results) 
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;
  const values = [id, title, summary, client, banner, logo, tags, challenge, solution, outcome, results];

  // Execute the query
  db.query(sql, values, (err, result) => {
    if (err) {
      console.error('Error adding data to casestudies table:', err);
      res.status(500).send('Error adding data to casestudies table');
      return;
    }
    res.status(201).send('Data added successfully');
  });
});

// app.post('/api/upload-image', upload.single('image'), async (req, res) => {
//   const file = req.file;
//   const sftp = new SftpClient();

//   try {
//     await sftp.connect({
//       host: 'server265.web-hosting.com',
//       port: 21098,
//       username: 'zimalxqv',
//       password: 'SnwnZ9vAvdKP',
//       readyTimeout: 20000 // Adjust the timeout value if needed
//     });

//     // Check if the destination directory exists, create it if it doesn't
//     const directoryExists = await sftp.exists('/public_html/images');
//     if (!directoryExists) {
//       await sftp.mkdir('/public_html/images/', true); // Recursive flag set to true
//     }

//     // Upload the file to the destination directory
//     await sftp.put(file.path, '/public_html/images/' + file.originalname);

//     res.send('File uploaded successfully');
//   } catch (error) {
//     console.error('Error:', error);
//     res.status(500).send('Error uploading file');
//   } finally {
//     try {
//       await sftp.end();
//     } catch (error) {
//       console.error('Error closing SFTP connection:', error);
//     }
//   }
// });

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
