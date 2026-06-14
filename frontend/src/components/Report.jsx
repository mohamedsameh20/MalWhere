import React, { useState } from 'react';
import VerdictBadge from './VerdictBadge';
import StepCard from './StepCard';

export default function Report({ report, steps, onReset }) {
  const [copiedIocs, setCopiedIocs] = useState({});
  const [copiedAll, setCopiedAll] = useState(false);

  const { verdict, confidence, summary, techniques, iocs } = report || {};

  // Find visualization base64 if it exists in steps
  const infoStep = (steps || []).find(s => s.tool === 'get_pe_info');
  const sha256 = infoStep?.result?.sha256;
  const visStep = (steps || []).find(s => s.tool === 'visualize_pe');

  const copyIoc = (ioc) => {
    navigator.clipboard.writeText(ioc);
    setCopiedIocs(prev => ({ ...prev, [ioc]: true }));
    setTimeout(() => {
      setCopiedIocs(prev => ({ ...prev, [ioc]: false }));
    }, 1500);
  };

  const copyAllIocs = () => {
    if (!iocs || iocs.length === 0) return;
    const text = iocs.join('\n');
    navigator.clipboard.writeText(text);
    setCopiedAll(true);
    setTimeout(() => {
      setCopiedAll(false);
    }, 1500);
  };

  return (
    <div className="report-container animate-fade-in">
      <div className="report-card">
        {/* 1. VERDICT BADGE */}
        <VerdictBadge verdict={verdict} confidence={confidence} />

        {/* 2. SUMMARY PARAGRAPH */}
        {summary && (
          <div className="report-section summary-section">
            <h3 className="section-title">Executive Summary</h3>
            <p className="summary-text">{summary}</p>
          </div>
        )}

        {/* 3. MITRE ATT&CK TECHNIQUES */}
        {techniques && techniques.length > 0 && (
          <div className="report-section">
            <h3 className="section-title">MITRE ATT&CK Techniques</h3>
            <div className="techniques-list">
              {techniques.map((tech, idx) => (
                <span key={idx} className="tech-badge">
                  {tech}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* 4. IOCs */}
        {iocs && iocs.length > 0 && (
          <div className="report-section">
            <div className="section-header-flex">
              <h3 className="section-title">Indicators of Compromise (IOCs)</h3>
              <button className="btn-copy-all" onClick={copyAllIocs}>
                {copiedAll ? 'Copied All!' : 'Copy All'}
              </button>
            </div>
            <div className="iocs-list">
              {iocs.map((ioc, idx) => (
                <div 
                  key={idx} 
                  className="ioc-item" 
                  onClick={() => copyIoc(ioc)}
                  title="Click to copy to clipboard"
                >
                  <code className="ioc-code">{ioc}</code>
                  <span className="ioc-copy-indicator">
                    {copiedIocs[ioc] ? 'Copied!' : 'Click to copy'}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* 5. PE VISUALIZATION */}
        {visStep && !visStep.result?.error && sha256 && (
          <div className="report-section visualization-section">
            <h3 className="section-title">PE Grayscale Byte Visualization</h3>
            <div className="vis-image-container">
              <img 
                src={`http://localhost:8000/analyze/image/${sha256}`} 
                alt="PE Visualization" 
                className="pe-vis-image"
              />
              <p className="pe-vis-caption">Byte Visualization (Width: 512px)</p>
            </div>
          </div>
        )}

        {/* 6. TOOL DETAILS (ACCORDIONS) */}
        {steps && steps.length > 0 && (
          <div className="report-section details-section">
            <h3 className="section-title">Detailed Analysis Steps</h3>
            <p className="section-description">Expand each card to inspect the tool parameters and raw tables.</p>
            <div className="steps-list">
              {steps.map((step, index) => (
                <StepCard key={index} step={step} sha256={sha256} />
              ))}
            </div>
          </div>
        )}

        {/* 7. RESET BUTTON */}
        <div className="reset-container">
          <button className="btn-primary reset-button" onClick={onReset}>
            Analyze Another File
          </button>
        </div>
      </div>
    </div>
  );
}
