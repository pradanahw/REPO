// Mock data for email analysis - simulates backend responses
export const mockData = {
  // Sample analysis results
  sampleAnalyses: [
    {
      classification: "PHISHING",
      confidence: 87,
      sender: "security@paypaI-verification.com",
      subject: "Urgent: Verify Your PayPaI Account Within 24 Hours",
      ipAddress: "185.220.101.45",
      location: {
        city: "Moscow",
        country: "Russia"
      },
      urlsDetected: 3,
      suspiciousWords: 8,
      analysisDate: new Date().toISOString()
    },
    {
      classification: "SAFE",
      confidence: 94,
      sender: "notifications@github.com",
      subject: "Your weekly GitHub activity summary",
      ipAddress: "140.82.112.3",
      location: {
        city: "San Francisco",
        country: "United States"
      },
      urlsDetected: 2,
      suspiciousWords: 0,
      analysisDate: new Date().toISOString()
    },
    {
      classification: "PHISHING",
      confidence: 76,
      sender: "noreply@amaz0n-security.net",
      subject: "Suspicious Activity Detected - Action Required",
      ipAddress: "91.234.56.78",
      location: {
        city: "Bucharest",
        country: "Romania"
      },
      urlsDetected: 5,
      suspiciousWords: 12,
      analysisDate: new Date().toISOString()
    },
    {
      classification: "SAFE",
      confidence: 91,
      sender: "team@slack.com",
      subject: "New message in #general channel",
      ipAddress: "54.230.142.33",
      location: {
        city: "Seattle",
        country: "United States"
      },
      urlsDetected: 1,
      suspiciousWords: 0,
      analysisDate: new Date().toISOString()
    },
    {
      classification: "PHISHING",
      confidence: 82,
      sender: "support@microsft-office.org",
      subject: "Your Office 365 subscription expires today",
      ipAddress: "103.21.244.8",
      location: {
        city: "Mumbai",
        country: "India"
      },
      urlsDetected: 4,
      suspiciousWords: 6,
      analysisDate: new Date().toISOString()
    }
  ],

  // Get a random analysis result
  getRandomAnalysis() {
    const randomIndex = Math.floor(Math.random() * this.sampleAnalyses.length);
    return { ...this.sampleAnalyses[randomIndex] };
  },

  // Get analysis by classification type
  getAnalysisByType(classification) {
    const filtered = this.sampleAnalyses.filter(
      analysis => analysis.classification === classification
    );
    if (filtered.length === 0) return this.getRandomAnalysis();
    
    const randomIndex = Math.floor(Math.random() * filtered.length);
    return { ...filtered[randomIndex] };
  },

  // Simulate API delay
  async simulateApiCall(delay = 2000) {
    return new Promise(resolve => {
      setTimeout(() => {
        resolve(this.getRandomAnalysis());
      }, delay);
    });
  }
};