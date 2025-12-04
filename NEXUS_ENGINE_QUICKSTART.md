<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# 🚀 NEXUS ENGINE™ Quick Start Guide
### Get Started in 60 Seconds

---

## ⚡ Instant Setup

### Step 1: Open the Engine (5 seconds)
```bash
# Option A: Direct file
Open NEXUS_ENGINE.html in your browser

# Option B: Local server
python3 -m http.server 8000
# Then visit: http://localhost:8000/NEXUS_ENGINE.html
```

### Step 2: Wait for Loading (2 seconds)
The engine automatically initializes with:
- ✅ 3D renderer
- ✅ Physics simulation
- ✅ Particle system
- ✅ Scene hierarchy
- ✅ Visual editor

### Step 3: Start Creating! (Immediate)
You're ready to build your game!

---

## 🎮 Your First 5 Minutes

### Minute 1: Explore the Demo Scene
- **Watch** the camera orbit the scene
- **Observe** physics objects (sphere & box)
- **Notice** 100+ particles floating
- **See** real-time lighting and shadows

### Minute 2: Play with Physics
1. Click **▶ Play** button
2. Watch objects get random physics impulses
3. See real-time physics simulation
4. Objects interact realistically

### Minute 3: Inspect the Scene
**Left Panel - Scene Hierarchy:**
- 🌍 Main Scene
- 💡 Directional Light
- 📷 Main Camera
- 🟦 Ground
- ⚽ Sphere
- 📦 Box
- 💫 Particles

**Click any object to select it**

### Minute 4: Edit Properties
**Right Panel - Properties:**
- Modify **Position** (X, Y, Z)
- Adjust **Rotation** (X, Y, Z)
- Change **Scale** (X, Y, Z)
- Edit **Material** properties
- Tweak **Physics** settings

### Minute 5: Use the Toolbar
**Top Toolbar:**
- 🖱️ **Select** - Click objects
- ↔️ **Move** - Transform position
- 🔄 **Rotate** - Rotate objects
- 📏 **Scale** - Resize objects
- 🏔️ **Terrain** - Sculpt terrain
- 🎨 **Paint** - Vertex painting

---

## 🎯 Common Tasks

### Add a New Object
```javascript
// Coming in visual editor update
// For now, edit the code directly

// Add a cylinder:
const cylinderGeo = new THREE.CylinderGeometry(0.5, 0.5, 2, 32);
const cylinderMat = new THREE.MeshStandardMaterial({
    color: 0xff0080,
    metalness: 0.7,
    roughness: 0.3
});
const cylinder = new THREE.Mesh(cylinderGeo, cylinderMat);
cylinder.position.set(0, 3, 0);
cylinder.castShadow = true;
scene.add(cylinder);

// Add physics:
const cylinderBody = new CANNON.Body({
    mass: 2,
    shape: new CANNON.Cylinder(0.5, 0.5, 2, 32),
    position: new CANNON.Vec3(0, 3, 0)
});
world.addBody(cylinderBody);
objs.push({mesh: cylinder, body: cylinderBody});
```

### Change Object Color
```javascript
// Select your object
sphere.material.color.setHex(0xff0080); // Magenta
box.material.color.setHex(0x00ff88);    // Green
```

### Modify Lighting
```javascript
// Make it brighter
dirLight.intensity = 5.0;

// Change color
dirLight.color.setHex(0x00d4ff); // Cyan light
```

### Add More Particles
```javascript
// Increase particle count
for(let i=0; i<200; i++) { // Changed from 100
    // ... particle creation code
}
```

### Apply Physics Forces
```javascript
// Apply upward force to sphere
sphereBody.applyImpulse(
    new CANNON.Vec3(0, 20, 0),
    sphereBody.position
);

// Apply spin to box
boxBody.applyTorque(new CANNON.Vec3(10, 10, 10));
```

---

## 📚 Learning Path

### Week 1: Fundamentals
- ✅ Day 1: Explore demo scene
- ✅ Day 2: Understand scene hierarchy
- ✅ Day 3: Modify properties
- ✅ Day 4: Experiment with physics
- ✅ Day 5: Change materials
- ✅ Day 6: Adjust lighting
- ✅ Day 7: Create first scene

### Week 2: Intermediate
- ⚡ Add custom objects
- ⚡ Create materials
- ⚡ Set up lighting
- ⚡ Configure physics
- ⚡ Build particle effects
- ⚡ Animate objects
- ⚡ Export project

### Week 3: Advanced
- 🚀 Custom shaders
- 🚀 Advanced physics
- 🚀 Optimization techniques
- 🚀 Performance tuning
- 🚀 Complex animations
- 🚀 Multi-scene management
- 🚀 Deploy to production

---

## 🎨 Example Projects

### Project 1: Bouncing Ball Game
**Goal:** Create a game where balls bounce around

**Steps:**
1. Remove demo objects
2. Create ground plane
3. Add multiple spheres
4. Apply random velocities
5. Add score counter
6. Implement click interaction

**Time:** 30 minutes

### Project 2: Product Showcase
**Goal:** Display 3D product with rotating camera

**Steps:**
1. Import/create product model
2. Set up PBR materials
3. Add dramatic lighting
4. Configure camera orbit
5. Add UI overlay
6. Deploy to web

**Time:** 1 hour

### Project 3: Physics Playground
**Goal:** Interactive physics sandbox

**Steps:**
1. Create various shapes
2. Add click-to-spawn
3. Implement drag & drop
4. Add force application
5. Create reset button
6. Add sound effects

**Time:** 2 hours

---

## 🔧 Customization Guide

### Change Color Scheme
```css
/* Edit in <style> section */
:root {
    --np: #your-color;  /* Primary */
    --ns: #your-color;  /* Secondary */
    --na: #your-color;  /* Accent */
}
```

### Modify Camera Settings
```javascript
// Edit in initEngine()
camera.position.set(x, y, z);
camera.lookAt(targetX, targetY, targetZ);

// Change FOV
camera.fov = 90; // Wider view
camera.updateProjectionMatrix();
```

### Adjust Physics Gravity
```javascript
// Edit in initEngine()
world.gravity.set(0, -20, 0); // Stronger gravity
// or
world.gravity.set(0, -5, 0);  // Moon gravity
```

### Change Particle Count
```javascript
// Find particle creation loop
for(let i=0; i<500; i++) { // More particles!
    // ... particle code
}
```

---

## 🐛 Troubleshooting

### Engine Won't Load
**Problem:** Black screen or no display

**Solutions:**
1. Check console for errors (F12)
2. Verify Three.js CDN is accessible
3. Verify Cannon.js CDN is accessible
4. Try different browser
5. Clear browser cache

### Low FPS
**Problem:** Performance below 60 FPS

**Solutions:**
1. Reduce particle count
2. Lower shadow map resolution
3. Disable shadows temporarily
4. Reduce object count
5. Simplify materials

### Physics Not Working
**Problem:** Objects not falling or colliding

**Solutions:**
1. Check object has physics body
2. Verify body has mass > 0
3. Check collision shapes match visuals
4. Verify world.step() is called
5. Check gravity is set

### Objects Not Visible
**Problem:** Added objects don't appear

**Solutions:**
1. Verify object added to scene
2. Check position is in camera view
3. Verify material is not transparent
4. Check lighting setup
5. Try different colors

---

## 💡 Pro Tips

### Performance Optimization
```javascript
// Use object pooling for particles
// Batch similar objects
// Use instanced rendering for many copies
// Implement frustum culling
// Use LOD (Level of Detail)
```

### Better Visuals
```javascript
// Increase shadow map size
dirLight.shadow.mapSize.width = 4096;
dirLight.shadow.mapSize.height = 4096;

// Add bloom effect
// Add ambient occlusion
// Use environment maps
// Add post-processing
```

### Smoother Physics
```javascript
// Increase solver iterations
world.solver.iterations = 20;

// Use better broadphase
world.broadphase = new CANNON.SAPBroadphase(world);
```

### Better Materials
```javascript
// Add environment map
const envMap = new THREE.CubeTextureLoader().load([...]);
material.envMap = envMap;
material.envMapIntensity = 1.5;

// Add normal maps
material.normalMap = texture;
material.normalScale = new THREE.Vector2(1, 1);
```

---

## 📦 Deployment Checklist

### Pre-Deploy
- [ ] Test in all browsers (Chrome, Firefox, Safari, Edge)
- [ ] Verify mobile responsiveness
- [ ] Optimize asset sizes
- [ ] Minify code
- [ ] Test loading time
- [ ] Check console for errors
- [ ] Verify all features work
- [ ] Test on slow connection

### Deploy
- [ ] Upload to CDN or hosting
- [ ] Configure HTTPS
- [ ] Set up caching headers
- [ ] Enable compression (gzip/brotli)
- [ ] Add meta tags for social sharing
- [ ] Create favicon
- [ ] Test deployed version
- [ ] Monitor analytics

### Post-Deploy
- [ ] Share with users
- [ ] Gather feedback
- [ ] Monitor performance
- [ ] Fix reported bugs
- [ ] Plan updates
- [ ] Iterate based on usage

---

## 🌐 Sharing Your Project

### Quick Share
```
1. Upload NEXUS_ENGINE.html to any web host
2. Share the URL
3. Done!
```

### Professional Share
```
1. Custom domain (yourproject.com)
2. HTTPS enabled
3. Open Graph tags for social media
4. Analytics tracking
5. Error monitoring
6. Performance monitoring
```

### Example Hosting Options
- **Free:** GitHub Pages, Netlify, Vercel, Cloudflare Pages
- **Paid:** AWS S3, Google Cloud, Azure, DigitalOcean
- **CDN:** Cloudflare, AWS CloudFront, Fastly

---

## 📞 Getting Help

### Resources
- 📖 **Documentation:** NEXUS_ENGINE_README.md
- 🔧 **Technical Specs:** NEXUS_ENGINE_SPECS.md
- ⚔️ **Comparisons:** NEXUS_VS_OTHER_ENGINES.md
- 💬 **Community:** [Coming Soon]
- 🐛 **Bug Reports:** [Coming Soon]
- 💡 **Feature Requests:** [Coming Soon]

### Learning Resources
- Three.js Documentation
- Cannon.js Documentation
- WebGL Fundamentals
- Game Development Patterns
- Physics Simulation Basics

---

## 🎯 Next Steps

### Beginner Path
1. ✅ Complete this quick start
2. → Modify demo scene colors
3. → Add a new object
4. → Change lighting
5. → Experiment with physics
6. → Build first simple game
7. → Deploy to web

### Intermediate Path
1. ✅ Master basic operations
2. → Create custom materials
3. → Build particle effects
4. → Implement animations
5. → Add interactivity
6. → Optimize performance
7. → Build portfolio piece

### Advanced Path
1. ✅ Understand engine architecture
2. → Write custom shaders
3. → Extend physics system
4. → Build custom tools
5. → Contribute improvements
6. → Create commercial project
7. → Launch product

---

## 🏆 Your First Hour Challenge

**Goal:** Create a simple game in 60 minutes

**Requirements:**
- ✅ Custom scene
- ✅ Player interaction
- ✅ Physics-based gameplay
- ✅ Score system
- ✅ Reset functionality
- ✅ Visual polish

**Example:** Physics Bowling
1. Create bowling pins (cylinders)
2. Create ball (sphere)
3. Add click-to-launch mechanic
4. Count knocked pins
5. Display score
6. Add reset button

---

**Ready to build something amazing?**

Open `NEXUS_ENGINE.html` and start creating! 🚀

---

*NEXUS ENGINE™ - From Zero to Game in 60 Seconds*

**Version:** 1.0  
**Last Updated:** 2025  
**Difficulty:** ⭐ Beginner Friendly
