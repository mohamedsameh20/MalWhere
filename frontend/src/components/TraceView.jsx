import React from 'react';
import StepCard from './StepCard';

export default function TraceView({ filename, steps, isRunning }) {
  return (
    <div className="trace-view-container">
      <div className="trace-view-header">
        <h2 className="trace-title">Analysis Progress</h2>
        <p className="trace-subtitle">File: <span className="trace-filename">{filename}</span></p>
      </div>

      <div className="steps-list">
        {steps.map((step, index) => (
          <StepCard key={index} step={step} />
        ))}
      </div>

      {isRunning && (
        <div className="thinking-container">
          <div className="spinner-pulsing"></div>
          <span className="thinking-text">Agent is thinking...</span>
        </div>
      )}
    </div>
  );
}
