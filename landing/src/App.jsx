import { motion } from "motion/react";
import { Plus } from "lucide-react";

const VIDEO_URL =
  "https://d8j0ntlcm91z4.cloudfront.net/user_38xzZboKViGWJOttwIXH07lWA1P/hf_20260508_215831_c6a8989c-d716-4d8d-8745-e972a2eec711.mp4";

const EASE = [0.16, 1, 0.3, 1];

function BrandMark() {
  return (
    <svg width="26" height="26" viewBox="0 0 48 48" fill="none" aria-hidden="true">
      <path d="M30 4 L8 4 L20 16 L8 16 L8 24 L30 24 L18 12 L30 12 Z" fill="currentColor" />
      <path d="M18 44 L40 44 L28 32 L40 32 L40 24 L18 24 L30 36 L18 36 Z" fill="currentColor" />
      <circle cx="24" cy="24" r="4.2" fill="currentColor" />
    </svg>
  );
}

function GridIcon() {
  return (
    <svg width="12" height="12" viewBox="0 0 12 12" fill="none" aria-hidden="true">
      <circle cx="2.5" cy="2.5" r="1.5" fill="#fff" />
      <circle cx="9.5" cy="2.5" r="1.5" fill="#fff" />
      <circle cx="2.5" cy="9.5" r="1.5" fill="#fff" />
      <circle cx="9.5" cy="9.5" r="1.5" fill="#fff" />
    </svg>
  );
}

export default function App() {
  return (
    <div className="page">
      <motion.nav
        className="navbar"
        initial={{ y: -16, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        transition={{ duration: 0.8, ease: EASE }}
      >
        <div className="nav-left">
          <div className="brand">
            <BrandMark />
            <span className="brand-name">SourceVenture</span>
          </div>

          <button className="menu-pill" type="button">
            <span className="menu-plus">
              <Plus size={12} strokeWidth={3} />
            </span>
            <span className="menu-label">Menu</span>
          </button>

          <div className="tags-pill">
            <span>AI Coach</span>
            <span>Investor Match</span>
          </div>
        </div>

        <div className="nav-right">
          <div className="tags-pill">
            <button className="dot-btn" type="button" aria-label="Founder platform">
              <GridIcon />
            </button>
            <span>Founder Platform</span>
          </div>
        </div>
      </motion.nav>

      <motion.div
        className="video-wrap"
        initial={{ opacity: 0, scale: 1.05 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ duration: 1.8, ease: EASE }}
      >
        <video
          className="bg-video"
          src={VIDEO_URL}
          autoPlay
          muted
          playsInline
          loop
        />
      </motion.div>

      <div className="footer">
        <motion.div
          className="footer-inner"
          initial={{ y: 20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ duration: 1, delay: 0.5, ease: EASE }}
        >
          <div className="footer-left">
            <motion.div
              className="footer-subtitle"
              initial={{ y: 16, opacity: 0 }}
              animate={{ y: 0, opacity: 1 }}
              transition={{ duration: 0.8, delay: 0.6, ease: EASE }}
            >
              <span className="dot" />
              AI-native venture engineering
            </motion.div>

            <motion.h1
              className="headline"
              initial={{ y: 20, opacity: 0 }}
              animate={{ y: 0, opacity: 1 }}
              transition={{ duration: 0.8, delay: 0.8, ease: EASE }}
            >
              One Coach, Zero
              <br />
              Guesswork. Grounded.
            </motion.h1>

            <motion.div
              className="cta-row"
              initial={{ y: 16, opacity: 0 }}
              animate={{ y: 0, opacity: 1 }}
              transition={{ duration: 0.8, delay: 1.0, ease: EASE }}
            >
              <button className="btn btn-primary" type="button">
                See Features
              </button>
              <button className="btn btn-secondary" type="button">
                How It Works
              </button>
            </motion.div>
          </div>

          <div className="footer-right">
            <span className="tag">AI Coach</span>
            <span className="tag">Investor Match</span>
            <span className="tag">Rating Council</span>
          </div>
        </motion.div>
      </div>
    </div>
  );
}
