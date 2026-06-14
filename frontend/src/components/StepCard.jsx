import React, { useState } from 'react';

const getToolIcon = (toolName) => {
  switch (toolName) {
    case 'get_pe_info':
      return (
        <svg className="step-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
          <polyline points="14 2 14 8 20 8" />
          <line x1="16" y1="13" x2="8" y2="13" />
          <line x1="16" y1="17" x2="8" y2="17" />
          <polyline points="10 9 9 9 8 9" />
        </svg>
      );
    case 'analyze_imports':
      return (
        <svg className="step-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
        </svg>
      );
    case 'scan_section_entropy':
      return (
        <svg className="step-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M3 3v18h18" />
          <path d="M18.7 8l-5.1 5.2-2.8-2.7L7 14.3" />
        </svg>
      );
    case 'extract_strings':
      return (
        <svg className="step-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" />
        </svg>
      );
    case 'scan_yara':
      return (
        <svg className="step-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
        </svg>
      );
    case 'ml_risk_score':
    case 'cnn_byte_score':
      return (
        <svg className="step-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <circle cx="12" cy="12" r="10" />
          <line x1="12" y1="16" x2="12" y2="12" />
          <line x1="12" y1="8" x2="12.01" y2="8" />
        </svg>
      );
    case 'hash_lookup':
    case 'threat_intel_lookup':
      return (
        <svg className="step-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <circle cx="11" cy="11" r="8" />
          <line x1="21" y1="21" x2="16.65" y2="16.65" />
        </svg>
      );
    case 'visualize_pe':
      return (
        <svg className="step-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <rect x="3" y="3" width="18" height="18" rx="2" ry="2" />
          <circle cx="8.5" cy="8.5" r="1.5" />
          <polyline points="21 15 16 10 5 21" />
        </svg>
      );
    default:
      return (
        <svg className="step-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <circle cx="12" cy="12" r="10" />
        </svg>
      );
  }
};

const formatResultSummary = (tool, result) => {
  if (!result) return 'No result returned.';
  if (result.error) return `Error: ${result.error}`;

  switch (tool) {
    case 'get_pe_info': {
      const sha = result.sha256 ? `${result.sha256.slice(0, 12)}...` : 'Unknown';
      const fileType = result.is_dll ? 'DLL' : result.is_exe ? 'EXE' : 'Unknown';
      const compileTime = result.compile_time ? result.compile_time.split('T')[0] : 'Unknown';
      return `SHA256: ${sha} | ${result.num_sections || 0} sections | ${fileType} | compiled ${compileTime}`;
    }
    case 'analyze_imports': {
      const flaggedCount = result.flagged ? result.flagged.length : 0;
      const highRiskCount = result.flagged ? result.flagged.filter(f => f.risk === 'high').length : 0;
      return `${result.total_imports || 0} imports | ${flaggedCount} flagged dangerous (${highRiskCount} high risk)`;
    }
    case 'scan_section_entropy': {
      if (!result.sections) return 'No sections parsed.';
      return result.sections
        .map(s => `${s.name}: ${s.entropy.toFixed(2)} (${s.flag || 'normal'})`)
        .join(' | ');
    }
    case 'extract_strings': {
      return `${result.total_extracted || 0} strings extracted | showing top ${result.showing || 0} classified`;
    }
    case 'scan_yara': {
      const matches = result.matches ? result.matches.length : 0;
      const failed = result.failed_rules !== undefined ? result.failed_rules : 0;
      return `${matches} YARA matches | ${failed} rules failed to compile`;
    }
    case 'ml_risk_score':
    case 'cnn_byte_score': {
      const scoreVal = result.score !== undefined ? result.score.toFixed(4) : 'N/A';
      return `Score: ${scoreVal} | Verdict: ${result.verdict || 'unknown'} (${result.model || 'unknown'})`;
    }
    case 'hash_lookup': {
      const known = result.is_known_malware ? 'YES' : 'NO';
      const mb = result.malware_bazaar ? result.malware_bazaar.status : 'skipped';
      const vt = result.virustotal ? result.virustotal.status : 'skipped';
      return `Known Malware: ${known} | MalwareBazaar: ${mb} | VirusTotal: ${vt}`;
    }
    case 'threat_intel_lookup': {
      const otx = result.alienvault_otx ? `${result.alienvault_otx.status} (${result.alienvault_otx.pulse_count || 0} pulses)` : 'skipped';
      const tf = result.threatfox ? result.threatfox.status : 'skipped';
      return `AlienVault OTX: ${otx} | ThreatFox: ${tf}`;
    }
    case 'visualize_pe': {
      return `Grayscale image generated (${result.image_width || 512}x${result.image_height || 0}) | Size: ${result.file_size_bytes || 0} bytes`;
    }
    default:
      return JSON.stringify(result).slice(0, 100) + '...';
  }
};

export default function StepCard({ step, sha256 }) {
  const [expanded, setExpanded] = useState(false);
  const { iteration, tool, reason, result } = step;

  const toggleExpand = () => {
    setExpanded(!expanded);
  };

  return (
    <div className="step-card animate-fade-in">
      <div className="step-card-header" onClick={toggleExpand}>
        <div className="step-number-badge">{iteration}</div>
        <div className="step-card-title-group">
          <div className="step-tool-name-container">
            {getToolIcon(tool)}
            <span className="step-tool-name">{tool}</span>
          </div>
          {reason && <p className="step-reason">{reason}</p>}
          <div className="step-result-summary">
            {formatResultSummary(tool, result)}
          </div>
        </div>
        <div className="step-expand-arrow">
          <svg 
            className={`arrow-icon ${expanded ? 'rotated' : ''}`} 
            viewBox="0 0 24 24" 
            fill="none" 
            stroke="currentColor" 
            strokeWidth="2"
          >
            <polyline points="6 9 12 15 18 9" />
          </svg>
        </div>
      </div>
      
      {expanded && (
        <div className="step-card-body">
          {tool === 'visualize_pe' && sha256 ? (
            <div className="visualize-preview">
              <img 
                src={`http://localhost:8000/analyze/image/${sha256}`} 
                alt="PE Grayscale Byte Visualization" 
                className="pe-vis-image"
              />
              <p className="pe-vis-caption">Byte Visualization (Width: 512px)</p>
            </div>
          ) : (
            <div className="table-wrapper">
              <table className="result-table">
                <tbody>
                  {Object.entries(result || {}).map(([key, val]) => {
                    // Do not display raw base64 or long nested lists in details directly
                    if (key === 'image_base64') return null;
                    let displayVal = '';
                    if (typeof val === 'object' && val !== null) {
                      displayVal = <pre className="raw-json">{JSON.stringify(val, null, 2)}</pre>;
                    } else {
                      displayVal = String(val);
                    }
                    return (
                      <tr key={key}>
                        <td className="table-key">{key}</td>
                        <td className="table-value">{displayVal}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
