import React from 'react';

export default function VerdictBadge({ verdict, confidence }) {
  const normalized = (verdict || '').toLowerCase();
  
  let bg = '#F3F4F6';
  let fg = '#374151';
  let text = 'UNKNOWN';
  
  if (normalized === 'malicious') {
    bg = '#FEE2E2';
    fg = '#EF4444';
    text = 'MALICIOUS';
  } else if (normalized === 'suspicious') {
    bg = '#FEF3C7';
    fg = '#D97706';
    text = 'SUSPICIOUS';
  } else if (normalized === 'clean') {
    bg = '#D1FAE5';
    fg = '#10B981';
    text = 'CLEAN';
  } else if (normalized === 'error') {
    bg = '#E5E7EB';
    fg = '#9CA3AF';
    text = 'ERROR';
  }

  return (
    <div className="verdict-container">
      <div className="verdict-badge" style={{ backgroundColor: bg, color: fg }}>
        {text}
      </div>
      {confidence !== undefined && (
        <div className="verdict-confidence">
          {confidence}% Confidence
        </div>
      )}
    </div>
  );
}
