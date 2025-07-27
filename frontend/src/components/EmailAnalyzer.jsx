import React, { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card';
import { Button } from './ui/button';
import { Alert, AlertDescription } from './ui/alert';
import { Badge } from './ui/badge';
import { Separator } from './ui/separator';
import { Upload, FileText, Shield, AlertTriangle, Download, Loader2, MapPin, Mail, Globe } from 'lucide-react';
import { useToast } from '../hooks/use-toast';

const EmailAnalyzer = () => {
  const [selectedFile, setSelectedFile] = useState(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [dragOver, setDragOver] = useState(false);
  const { toast } = useToast();

  const handleFileSelect = (event) => {
    const file = event.target.files[0];
    validateAndSetFile(file);
  };

  const handleDrop = (event) => {
    event.preventDefault();
    setDragOver(false);
    const file = event.dataTransfer.files[0];
    validateAndSetFile(file);
  };

  const validateAndSetFile = (file) => {
    if (!file) return;
    
    if (!file.name.toLowerCase().endsWith('.eml')) {
      toast({
        title: "Invalid file format",
        description: "Please select a .eml email file",
        variant: "destructive"
      });
      return;
    }

    if (file.size > 10 * 1024 * 1024) { // 10MB limit
      toast({
        title: "File too large",
        description: "Please select a file smaller than 10MB",
        variant: "destructive"
      });
      return;
    }

    setSelectedFile(file);
    setAnalysisResult(null);
  };

  const handleAnalyze = async () => {
    if (!selectedFile) return;

    setIsAnalyzing(true);
    
    try {
      // Create FormData for file upload
      const formData = new FormData();
      formData.append('file', selectedFile);
      
      // Make API call to backend
      const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
      const response = await fetch(`${BACKEND_URL}/api/analyze`, {
        method: 'POST',
        body: formData,
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Analysis failed');
      }
      
      const result = await response.json();
      setAnalysisResult(result);
      
      toast({
        title: "Analysis complete",
        description: `Email classified as ${result.classification}`,
        variant: result.classification === "SAFE" ? "default" : "destructive"
      });
      
    } catch (error) {
      toast({
        title: "Analysis failed",
        description: error.message || "An error occurred during analysis. Please try again.",
        variant: "destructive"
      });
    } finally {
      setIsAnalyzing(false);
    }
  };

  const downloadCSV = async () => {
    if (!analysisResult || !analysisResult.id) return;

    try {
      const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
      const response = await fetch(`${BACKEND_URL}/api/analysis/${analysisResult.id}/csv`);
      
      if (!response.ok) {
        throw new Error('Failed to download CSV');
      }
      
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `email-analysis-${Date.now()}.csv`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);

      toast({
        title: "Download started",
        description: "Analysis results downloaded as CSV"
      });
      
    } catch (error) {
      toast({
        title: "Download failed",
        description: error.message || "Failed to download CSV file",
        variant: "destructive"
      });
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-blue-50 p-4">
      <div className="max-w-6xl mx-auto space-y-8">
        {/* Header */}
        <div className="text-center space-y-4 py-12">
          <div className="flex items-center justify-center space-x-3 mb-4">
            <Shield className="h-12 w-12 text-blue-600" />
            <h1 className="text-5xl font-bold bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent">
              AI Phishing Detector
            </h1>
          </div>
          <p className="text-xl text-gray-600 max-w-2xl mx-auto">
            Advanced machine learning-powered email analysis to detect phishing attempts and protect your digital security
          </p>
        </div>

        <div className="grid lg:grid-cols-2 gap-8">
          {/* Upload Section */}
          <Card className="shadow-xl border-0 bg-white/80 backdrop-blur-lg">
            <CardHeader className="space-y-2">
              <CardTitle className="flex items-center space-x-2 text-2xl">
                <Upload className="h-6 w-6 text-blue-600" />
                <span>Upload Email File</span>
              </CardTitle>
              <CardDescription className="text-base">
                Select a .eml email file to analyze for potential phishing threats
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              {/* File Drop Zone */}
              <div
                className={`relative border-2 border-dashed rounded-xl p-8 text-center transition-all duration-300 ${
                  dragOver
                    ? 'border-blue-500 bg-blue-50 scale-105'
                    : selectedFile
                    ? 'border-green-500 bg-green-50'
                    : 'border-gray-300 hover:border-blue-400 hover:bg-blue-50/50'
                }`}
                onDragOver={(e) => {
                  e.preventDefault();
                  setDragOver(true);
                }}
                onDragLeave={() => setDragOver(false)}
                onDrop={handleDrop}
              >
                <input
                  type="file"
                  accept=".eml"
                  onChange={handleFileSelect}
                  className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                />
                
                <div className="space-y-4">
                  {selectedFile ? (
                    <div className="space-y-3">
                      <FileText className="h-16 w-16 text-green-600 mx-auto" />
                      <div>
                        <p className="font-semibold text-green-700">{selectedFile.name}</p>
                        <p className="text-sm text-gray-500">
                          {(selectedFile.size / 1024).toFixed(1)} KB
                        </p>
                      </div>
                    </div>
                  ) : (
                    <div className="space-y-3">
                      <Upload className="h-16 w-16 text-gray-400 mx-auto" />
                      <div>
                        <p className="text-lg font-medium text-gray-700">
                          Drag & drop your .eml file here
                        </p>
                        <p className="text-gray-500">or click to browse</p>
                      </div>
                    </div>
                  )}
                </div>
              </div>

              {/* Analyze Button */}
              <Button
                onClick={handleAnalyze}
                disabled={!selectedFile || isAnalyzing}
                size="lg"
                className="w-full bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 text-white shadow-lg transform transition-all duration-200 hover:scale-105"
              >
                {isAnalyzing ? (
                  <>
                    <Loader2 className="h-5 w-5 mr-2 animate-spin" />
                    Analyzing Email...
                  </>
                ) : (
                  <>
                    <Shield className="h-5 w-5 mr-2" />
                    Analyze Email
                  </>
                )}
              </Button>

              {/* Status Messages */}
              {isAnalyzing && (
                <Alert className="border-blue-200 bg-blue-50">
                  <Loader2 className="h-4 w-4 animate-spin" />
                  <AlertDescription className="font-medium">
                    Processing email with AI models... This may take a few moments.
                  </AlertDescription>
                </Alert>
              )}
            </CardContent>
          </Card>

          {/* Results Section */}
          <Card className="shadow-xl border-0 bg-white/80 backdrop-blur-lg">
            <CardHeader>
              <CardTitle className="flex items-center space-x-2 text-2xl">
                <FileText className="h-6 w-6 text-purple-600" />
                <span>Analysis Results</span>
              </CardTitle>
              <CardDescription className="text-base">
                Detailed security analysis and threat assessment
              </CardDescription>
            </CardHeader>
            <CardContent>
              {!analysisResult ? (
                <div className="text-center py-12 space-y-4">
                  <div className="h-24 w-24 mx-auto bg-gray-100 rounded-full flex items-center justify-center">
                    <Shield className="h-12 w-12 text-gray-400" />
                  </div>
                  <p className="text-gray-500 text-lg">
                    Upload and analyze an email to see results here
                  </p>
                </div>
              ) : (
                <div className="space-y-6">
                  {/* Classification Result */}
                  <div className="text-center p-6 rounded-xl bg-gradient-to-r from-gray-50 to-gray-100">
                    <Badge
                      variant={analysisResult.classification === 'SAFE' ? 'default' : 'destructive'}
                      className={`text-lg px-6 py-2 ${
                        analysisResult.classification === 'SAFE'
                          ? 'bg-green-100 text-green-800 hover:bg-green-200'
                          : 'bg-red-100 text-red-800 hover:bg-red-200'
                      }`}
                    >
                      {analysisResult.classification === 'SAFE' ? (
                        <Shield className="h-5 w-5 mr-2" />
                      ) : (
                        <AlertTriangle className="h-5 w-5 mr-2" />
                      )}
                      {analysisResult.classification}
                    </Badge>
                  </div>

                  <Separator />

                  {/* Email Details */}
                  <div className="space-y-4">
                    <div className="grid gap-4">
                      <div className="flex items-start space-x-3">
                        <Mail className="h-5 w-5 text-blue-600 mt-0.5" />
                        <div className="flex-1">
                          <p className="font-semibold text-gray-800">Sender</p>
                          <p className="text-gray-600 break-all">{analysisResult.sender}</p>
                        </div>
                      </div>

                      <div className="flex items-start space-x-3">
                        <FileText className="h-5 w-5 text-purple-600 mt-0.5" />
                        <div className="flex-1">
                          <p className="font-semibold text-gray-800">Subject</p>
                          <p className="text-gray-600">{analysisResult.subject}</p>
                        </div>
                      </div>

                      {analysisResult.ip_address && (
                        <div className="flex items-start space-x-3">
                          <Globe className="h-5 w-5 text-orange-600 mt-0.5" />
                          <div className="flex-1">
                            <p className="font-semibold text-gray-800">IP Address</p>
                            <p className="text-gray-600 font-mono">{analysisResult.ip_address}</p>
                          </div>
                        </div>
                      )}

                      {analysisResult.location && (
                        <div className="flex items-start space-x-3">
                          <MapPin className="h-5 w-5 text-red-600 mt-0.5" />
                          <div className="flex-1">
                            <p className="font-semibold text-gray-800">Location</p>
                            <p className="text-gray-600">
                              {analysisResult.location.city}, {analysisResult.location.country}
                            </p>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>

                  <Separator />

                  {/* Technical Details */}
                  <div className="space-y-3">
                    <h4 className="font-semibold text-gray-800">Technical Analysis</h4>
                    <div className="grid grid-cols-1 gap-3">
                      <div className="flex justify-between items-center">
                        <span className="text-gray-600">URLs Detected:</span>
                        <Badge variant="outline">{analysisResult.urls_detected}</Badge>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-gray-600">Suspicious Words:</span>
                        <Badge variant="outline">{analysisResult.suspicious_words}</Badge>
                      </div>
                    </div>
                  </div>

                  {/* Download Button */}
                  <Button
                    onClick={downloadCSV}
                    variant="outline"
                    className="w-full border-gray-300 hover:bg-gray-50"
                  >
                    <Download className="h-4 w-4 mr-2" />
                    Download Results as CSV
                  </Button>
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Features Section */}
        <div className="grid md:grid-cols-3 gap-6 mt-12">
          <Card className="border-0 bg-white/60 backdrop-blur-sm">
            <CardContent className="p-6 text-center space-y-3">
              <div className="h-12 w-12 mx-auto bg-blue-100 rounded-full flex items-center justify-center">
                <Shield className="h-6 w-6 text-blue-600" />
              </div>
              <h3 className="font-semibold text-gray-800">AI-Powered Detection</h3>
              <p className="text-gray-600 text-sm">
                Advanced machine learning models trained on thousands of phishing examples
              </p>
            </CardContent>
          </Card>

          <Card className="border-0 bg-white/60 backdrop-blur-sm">
            <CardContent className="p-6 text-center space-y-3">
              <div className="h-12 w-12 mx-auto bg-purple-100 rounded-full flex items-center justify-center">
                <Globe className="h-6 w-6 text-purple-600" />
              </div>
              <h3 className="font-semibold text-gray-800">Geolocation Analysis</h3>
              <p className="text-gray-600 text-sm">
                Track sender locations and identify suspicious geographic patterns
              </p>
            </CardContent>
          </Card>

          <Card className="border-0 bg-white/60 backdrop-blur-sm">
            <CardContent className="p-6 text-center space-y-3">
              <div className="h-12 w-12 mx-auto bg-green-100 rounded-full flex items-center justify-center">
                <Download className="h-6 w-6 text-green-600" />
              </div>
              <h3 className="font-semibold text-gray-800">Detailed Reports</h3>
              <p className="text-gray-600 text-sm">
                Export comprehensive analysis results in CSV format for record keeping
              </p>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
};

export default EmailAnalyzer;