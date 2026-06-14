import React, { useState } from 'react';
import Dropzone from './components/Dropzone';
import TraceView from './components/TraceView';
import Report from './components/Report';
import './App.css';

const API_URL = "http://localhost:8000";

export default function App() {
  const [phase, setPhase] = useState("idle"); // idle | running | complete
  const [file, setFile] = useState(null);
  const [steps, setSteps] = useState([]);
  const [report, setReport] = useState(null);
  const [errorMessage, setErrorMessage] = useState("");

  const startAnalysis = async (selectedFile) => {
    setFile(selectedFile);
    setPhase("running");
    setSteps([]);
    setReport(null);
    setErrorMessage("");

    try {
      const formData = new FormData();
      formData.append("file", selectedFile);

      const response = await fetch(`${API_URL}/analyze/stream`, {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        let errText = "Failed to start analysis server-side.";
        try {
          const errData = await response.json();
          errText = errData.detail || errText;
        } catch (_) {}
        throw new Error(errText);
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      const processBuffer = (text) => {
        const lines = text.split("\n");
        let remaining = lines.pop(); // keep incomplete line
        
        let currentEvent = "";
        for (const line of lines) {
          const trimmedLine = line.trim();
          if (!trimmedLine) continue;

          if (trimmedLine.startsWith("event:")) {
            currentEvent = trimmedLine.slice(6).trim();
          } else if (trimmedLine.startsWith("data:")) {
            try {
              const data = JSON.parse(trimmedLine.slice(5).trim());
              
              if (currentEvent === "step") {
                setSteps(prev => [...prev, data]);
              } else if (currentEvent === "report") {
                setReport(data.report);
                if (data.steps && data.steps.length > 0) {
                  setSteps(data.steps);
                }
                setPhase("complete");
              } else if (currentEvent === "cached") {
                setReport(data.report);
                if (data.steps && data.steps.length > 0) {
                  setSteps(data.steps);
                }
                setPhase("complete");
              } else if (currentEvent === "error") {
                setErrorMessage(data.error || "An error occurred during analysis.");
                setPhase("complete");
              } else if (currentEvent === "done") {
                setPhase("complete");
              }
            } catch (err) {
              console.error("Failed to parse SSE JSON payload", err);
            }
          }
        }
        return remaining;
      };

      while (true) {
        const { done, value } = await reader.read();
        if (value) {
          buffer += decoder.decode(value, { stream: true });
          buffer = processBuffer(buffer);
        }
        if (done) {
          if (buffer.trim()) {
            processBuffer(buffer + "\n");
          }
          setPhase("complete");
          break;
        }
      }
    } catch (error) {
      console.error("Analysis stream encountered an error:", error);
      setErrorMessage(error.message || "Could not connect to the analysis server. Make sure the backend is running.");
      setPhase("complete");
      setReport({
        verdict: "error",
        confidence: 0,
        summary: error.message || "An error occurred while streaming analysis.",
        techniques: [],
        iocs: []
      });
    }
  };

  const handleReset = () => {
    setFile(null);
    setSteps([]);
    setReport(null);
    setErrorMessage("");
    setPhase("idle");
  };

  return (
    <div className="app-container">
      <header className="app-header">
        <h1 className="logo-text">Mal<span>Where</span></h1>
        <p className="logo-subtitle">Local ReAct Agent for Windows PE Malware Analysis</p>
      </header>

      <main className="app-main">
        {phase === "idle" && (
          <Dropzone onFileSelected={startAnalysis} />
        )}

        {phase === "running" && file && (
          <TraceView 
            filename={file.name} 
            steps={steps} 
            isRunning={true} 
          />
        )}

        {phase === "complete" && (
          <Report 
            report={report} 
            steps={steps} 
            onReset={handleReset} 
          />
        )}
      </main>
    </div>
  );
}
