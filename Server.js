// ══════════════════════════════════════════════════════
//  RYTHUM HUB — Backend Server
//  Stack: Node.js + Express + MongoDB (Mongoose)
//  Auth:  JWT (JSON Web Tokens)
// ══════════════════════════════════════════════════════

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
require('dotenv').config();

const app = express();

// ── MIDDLEWARE ──────────────────────────────────────────
app.use(cors({
    origin: process.env.CLIENT_URL || '*',
    credentials: true
}));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public'))); // serve HTML/CSS/JS
app.use('/songs', express.static(path.join(__dirname, 'songs'))); // serve audio files

// ── MONGODB CONNECTION ──────────────────────────────────
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/rythumhub';
mongoose.connect(MONGO_URI)
    .then(() => console.log('✅ MongoDB connected:', MONGO_URI))
    .catch(err => console.error('❌ MongoDB error:', err.message));

// ── SCHEMAS / MODELS ────────────────────────────────────

// User
const userSchema = new mongoose.Schema({
    name:      { type: String, required: true, trim: true },
    email:     { type: String, required: true, unique: true, lowercase: true, trim: true },
    password:  { type: String, required: true, minlength: 6 },
    avatar:    { type: String, default: '' },
    likedSongs:   [{ type: mongoose.Schema.Types.ObjectId, ref: 'Song' }],
    followedArtists: [{ type: String }],
    createdAt: { type: Date, default: Date.now }
});
// Hash password before save
userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    this.password = await bcrypt.hash(this.password, 12);
    next();
});
// Compare password
userSchema.methods.comparePassword = function(plain) {
    return bcrypt.compare(plain, this.password);
};
const User = mongoose.model('User', userSchema);

// Song
const songSchema = new mongoose.Schema({
    rank:     { type: Number, default: 0 },
    title:    { type: String, required: true, trim: true },
    artist:   { type: String, required: true, trim: true },
    genre:    { type: String, default: '' },
    file:     { type: String, required: true }, // filename in /songs/
    trending: { type: Boolean, default: false },
    plays:    { type: Number, default: 0 },
    likes:    { type: Number, default: 0 },
    duration: { type: Number, default: 0 }, // seconds
    cover:    { type: String, default: '' }, // URL or filename
    addedAt:  { type: Date, default: Date.now }
});
const Song = mongoose.model('Song', songSchema);

// Play log (analytics)
const playLogSchema = new mongoose.Schema({
    song:      { type: mongoose.Schema.Types.ObjectId, ref: 'Song' },
    user:      { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    playedAt:  { type: Date, default: Date.now },
    ip:        { type: String }
});
const PlayLog = mongoose.model('PlayLog', playLogSchema);

// ── JWT HELPER ──────────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET || 'rythum_hub_super_secret_2026';
const JWT_EXPIRES = process.env.JWT_EXPIRES || '7d';

function signToken(userId) {
    return jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: JWT_EXPIRES });
}

// ── AUTH MIDDLEWARE ─────────────────────────────────────
async function protect(req, res, next) {
    const auth = req.headers.authorization;
    if (!auth || !auth.startsWith('Bearer ')) {
        return res.status(401).json({ success: false, message: 'Not authenticated' });
    }
    try {
        const decoded = jwt.verify(auth.split(' ')[1], JWT_SECRET);
        req.user = await User.findById(decoded.id).select('-password');
        if (!req.user) return res.status(401).json({ success: false, message: 'User not found' });
        next();
    } catch (e) {
        res.status(401).json({ success: false, message: 'Invalid or expired token' });
    }
}

// Optional auth — doesn't block, but attaches user if token valid
async function softAuth(req, res, next) {
    const auth = req.headers.authorization;
    if (auth && auth.startsWith('Bearer ')) {
        try {
            const decoded = jwt.verify(auth.split(' ')[1], JWT_SECRET);
            req.user = await User.findById(decoded.id).select('-password');
        } catch {}
    }
    next();
}

// ══════════════════════════════════════════════════════
//  ROUTES
// ══════════════════════════════════════════════════════

// ── AUTH ────────────────────────────────────────────────

// POST /api/auth/register
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        if (!name || !email || !password)
            return res.status(400).json({ success: false, message: 'All fields are required' });
        if (password.length < 6)
            return res.status(400).json({ success: false, message: 'Password must be at least 6 characters' });

        const exists = await User.findOne({ email });
        if (exists)
            return res.status(409).json({ success: false, message: 'Email already registered' });

        const user = await User.create({ name, email, password });
        const token = signToken(user._id);

        res.status(201).json({
            success: true,
            token,
            user: { id: user._id, name: user.name, email: user.email, avatar: user.avatar }
        });
    } catch (e) {
        console.error('Register error:', e);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password)
            return res.status(400).json({ success: false, message: 'Email and password required' });

        const user = await User.findOne({ email });
        if (!user || !(await user.comparePassword(password)))
            return res.status(401).json({ success: false, message: 'Invalid email or password' });

        const token = signToken(user._id);

        res.json({
            success: true,
            token,
            user: { id: user._id, name: user.name, email: user.email, avatar: user.avatar }
        });
    } catch (e) {
        console.error('Login error:', e);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// GET /api/auth/me  — verify token & get current user
app.get('/api/auth/me', protect, (req, res) => {
    res.json({
        success: true,
        user: {
            id: req.user._id,
            name: req.user.name,
            email: req.user.email,
            avatar: req.user.avatar,
            likedSongs: req.user.likedSongs,
            followedArtists: req.user.followedArtists
        }
    });
});

// PUT /api/auth/profile — update name/avatar
app.put('/api/auth/profile', protect, async (req, res) => {
    try {
        const { name, avatar } = req.body;
        const updates = {};
        if (name) updates.name = name;
        if (avatar) updates.avatar = avatar;
        const user = await User.findByIdAndUpdate(req.user._id, updates, { new: true }).select('-password');
        res.json({ success: true, user });
    } catch (e) {
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// PUT /api/auth/password — change password
app.put('/api/auth/password', protect, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        const user = await User.findById(req.user._id);
        if (!(await user.comparePassword(currentPassword)))
            return res.status(400).json({ success: false, message: 'Current password is incorrect' });
        if (newPassword.length < 6)
            return res.status(400).json({ success: false, message: 'New password must be at least 6 characters' });
        user.password = newPassword;
        await user.save();
        res.json({ success: true, message: 'Password updated' });
    } catch (e) {
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// ── SONGS ───────────────────────────────────────────────

// GET /api/songs — get all songs (with optional filter)
app.get('/api/songs', async (req, res) => {
    try {
        const { genre, trending, search, limit = 50 } = req.query;
        const query = {};
        if (genre) query.genre = { $regex: genre, $options: 'i' };
        if (trending === 'true') query.trending = true;
        if (search) query.$or = [
            { title:  { $regex: search, $options: 'i' } },
            { artist: { $regex: search, $options: 'i' } }
        ];
        const songs = await Song.find(query).sort({ rank: 1 }).limit(parseInt(limit));
        res.json({ success: true, data: songs, count: songs.length });
    } catch (e) {
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// GET /api/songs/:id
app.get('/api/songs/:id', async (req, res) => {
    try {
        const song = await Song.findById(req.params.id);
        if (!song) return res.status(404).json({ success: false, message: 'Song not found' });
        res.json({ success: true, data: song });
    } catch (e) {
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// POST /api/songs/:id/play — increment play count
app.post('/api/songs/:id/play', softAuth, async (req, res) => {
    try {
        const song = await Song.findByIdAndUpdate(
            req.params.id,
            { $inc: { plays: 1 } },
            { new: true }
        );
        if (!song) return res.status(404).json({ success: false, message: 'Song not found' });
        // Log play
        await PlayLog.create({
            song: song._id,
            user: req.user?._id || null,
            ip: req.ip
        });
        res.json({ success: true, plays: song.plays });
    } catch (e) {
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// POST /api/songs/:id/like — toggle like
app.post('/api/songs/:id/like', protect, async (req, res) => {
    try {
        const song = await Song.findById(req.params.id);
        if (!song) return res.status(404).json({ success: false, message: 'Song not found' });

        const user = await User.findById(req.user._id);
        const alreadyLiked = user.likedSongs.includes(song._id);

        if (alreadyLiked) {
            user.likedSongs.pull(song._id);
            song.likes = Math.max(0, song.likes - 1);
        } else {
            user.likedSongs.push(song._id);
            song.likes += 1;
        }
        await Promise.all([user.save(), song.save()]);
        res.json({ success: true, liked: !alreadyLiked, likes: song.likes });
    } catch (e) {
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// GET /api/songs/liked — get user's liked songs
app.get('/api/songs/liked/list', protect, async (req, res) => {
    try {
        const user = await User.findById(req.user._id).populate('likedSongs');
        res.json({ success: true, data: user.likedSongs });
    } catch (e) {
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// ── SEED SONGS (run once to populate DB) ───────────────
// POST /api/admin/seed   — protected, admin use only
app.post('/api/admin/seed', async (req, res) => {
    const { adminKey } = req.body;
    if (adminKey !== (process.env.ADMIN_KEY || 'rythum_admin_2026'))
        return res.status(403).json({ success: false, message: 'Forbidden' });

    const songs = [
        {rank:1, title:'Tu Banja Gali Benaras Ki', artist:'Asees Kaur',        genre:'Devotional', file:'409081-asees-kaur---tu-banja-gali-benaras-ki-feat.-asees-kaur.mp3',                                                                              trending:true},
        {rank:2, title:'Baithe Baithe',            artist:'Aishwarya Pandit',   genre:'Romantic',   file:'524094-aishwarya-pandit---baithe-baithe.mp3',                                                                                                    trending:false},
        {rank:3, title:'Tujh Mein Rab Dikhta Hai', artist:'Roop Kumar Rathod',  genre:'Bollywood',  file:'540056-127978-tujh-mein-rab-dikhta-hai-song-_-rab-ne-bana-di-jodi-_-shah-rukh-khan,-anushka-sharma-_-roop-kumar.mp3',                            trending:true},
        {rank:4, title:'Tere Sang Yaara Remix',    artist:'Atif Aslam',         genre:'Romantic',   file:'666910-atif-aslam---tere-sang-yaara---remix.mp3',                                                                                                trending:true},
        {rank:5, title:'Marziyan',                 artist:'Arijit Singh',       genre:'Romantic',   file:'Arijit_Singh_s_New_Romantic_Song__Marziyan__-_The_Love_Anthem_That_Will_Make_You_Fall_in_Love!(256k).mp3',                                        trending:true},
        {rank:6, title:'Ishq Hai Tamil Kadhale',   artist:'Armaan Malik',       genre:'Fusion',     file:'Hindi_Ishq_hai_Tamil_Kadhale_lyrics___Nodivalandava_Lyrics__Arjun_Janya___Armaan_Malik,Shreya_Ghosal(256k).mp3',                                  trending:false},
        {rank:7, title:'Hoshwalon Ko Khabar Kya',  artist:'Jagjit Singh',       genre:'Ghazal',     file:'Hoshwalon_Ko_Khabar_Kya___JAGJIT_SINGH___Sarfarosh___1999(128k).mp3',                                                                            trending:false},
        {rank:8, title:'Kahani Meri',              artist:'Kaifi Khalil',       genre:'Indie',      file:'Kahani_Meri_official_Lyrical_Video___kaifi_Khalil___Anmol_Daniel_I_Novice_Records(128k).mp3',                                                     trending:true},
        {rank:9, title:'Barbaad — Saiyaara',       artist:'Jubin Nautiyal',     genre:'Romantic',   file:'Lyrical___Barbaad_Song___Saiyaara___Ahaan_Panday,_Aneet_Padda___The_Rish___Jubin_Nautiyal(256k).mp3',                                             trending:true},
        {rank:10,title:'Aaoge Jab Tum',            artist:'Ustad Rashid Khan',  genre:'Ghazal',     file:'Lyrical__Aaoge_Jab_Tum___Jab_We_Met___Kareena__Kapoor,_Shahid_Kapoor___Ustad_Rashid_Khan(128k).mp3',                                             trending:false},
        {rank:11,title:'Main Pal Do Pal Ka Shayar',artist:'Mukesh, Amitabh',    genre:'Classic',    file:'Main_Pal_Do_Pal_Ka_Shayar_Hoon____Jhankar____Mukesh_Chand_Mathur,_Amitabh_Bachchan___Shashi_Kapoor(256k).mp3',                                   trending:false},
        {rank:12,title:'Bollywood Mix',            artist:'Various Artists',    genre:'Bollywood',  file:'mondamusic-bollywood-indian-hindi-song-music-499178.mp3',                                                                                          trending:false},
        {rank:13,title:'Rubaru',                   artist:'Vishal Mishra',      genre:'Romantic',   file:'Rubaru___Khuda_Haafiz_2___Vidyut_J,_Shivaleeka_O___Vishal_Mishra,_Asees_Kaur,_Manoj_M___Lyrical(256k).mp3',                                       trending:true},
        {rank:14,title:'The Mountain',             artist:'Instrumental',       genre:'Ambient',    file:'the_mountain-indian-hindi-background-music-496551.mp3',                                                                                            trending:false},
    ];

    try {
        await Song.deleteMany({});
        const inserted = await Song.insertMany(songs);
        res.json({ success: true, message: `Seeded ${inserted.length} songs`, data: inserted });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

// ── ANALYTICS ───────────────────────────────────────────
// GET /api/analytics/top — top played songs
app.get('/api/analytics/top', async (req, res) => {
    try {
        const top = await Song.find().sort({ plays: -1 }).limit(10).select('title artist plays genre');
        res.json({ success: true, data: top });
    } catch (e) {
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// ── HEALTH CHECK ────────────────────────────────────────
app.get('/api/health', (req, res) => {
    res.json({
        success: true,
        status: 'running',
        time: new Date().toISOString(),
        db: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
    });
});

// ── SERVE FRONTEND (SPA fallback) ──────────────────────
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── START SERVER ────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`\n🎵 RYTHUM HUB Server running`);
    console.log(`   Local:  http://localhost:${PORT}`);
    console.log(`   DB:     ${MONGO_URI}`);
    console.log(`   Mode:   ${process.env.NODE_ENV || 'development'}\n`);
});