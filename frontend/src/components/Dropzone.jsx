import React, { useState, useRef } from 'react';

export default function Dropzone({ onFileSelected }) {
  const [isDragActive, setIsDragActive] = useState(false);
  const [error, setError] = useState('');
  const fileInputRef = useRef(null);

  const validateAndSelectFile = (file) => {
    if (!file) return;
    setError('');

    const name = file.name || '';
    if (!name.toLowerCase().endswith?.('.exe') && !name.toLowerCase().endsWith('.dll') && !name.toLowerCase().endsWith('.exe')) {
      setError('Only .exe and .dll files are accepted.');
      return;
    }

    if (file.size > 10 * 1024 * 1024) {
      setError('File exceeds the 10MB limit.');
      return;
    }

    onFileSelected(file);
  };

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setIsDragActive(true);
    } else if (e.type === 'dragleave') {
      setIsDragActive(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragActive(false);

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      validateAndSelectFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      validateAndSelectFile(e.target.files[0]);
    }
  };

  const handleButtonClick = () => {
    fileInputRef.current.click();
  };

  return (
    <div className="dropzone-wrapper">
      <div 
        className={`dropzone-container ${isDragActive ? 'drag-active' : ''}`}
        onDragEnter={handleDrag}
        onDragOver={handleDrag}
        onDragLeave={handleDrag}
        onDrop={handleDrop}
        onClick={handleButtonClick}
      >
        <input 
          ref={fileInputRef}
          type="file" 
          accept=".exe,.dll" 
          style={{ display: 'none' }}
          onChange={handleFileChange}
        />
        <div className="dropzone-content">
          <svg className="dropzone-icon" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
          </svg>
          <p className="dropzone-text-primary">
            Drag & drop a <span className="highlight">.exe</span> or <span className="highlight">.dll</span> file here
          </p>
          <p className="dropzone-text-secondary">
            or click to browse local files
          </p>
          <p className="dropzone-text-size">
            Maximum file size: 10MB
          </p>
        </div>
      </div>
      {error && <div className="dropzone-error">{error}</div>}
    </div>
  );
}
