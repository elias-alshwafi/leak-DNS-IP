"""
Advanced Content Analyzer for Intelligence X CLI
"""

import re
from collections import Counter
import hashlib
import json
from typing import List, Dict, Any, Tuple

class ContentAnalyzer:
    """Advanced content analyzer with multiple analysis capabilities"""
    
    def __init__(self):
        self.patterns = {
            'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'ipv4': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            'url': r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*',
            'bitcoin': r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}',
            'credit_card': r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
            'phone': r'(?:\+\d{1,3}[-\s]?)?\(?\d{3}\)?[-\s]?\d{3}[-\s]?\d{4}',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'domain': r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'
        }
    
    def analyze_content(self, content: str) -> Dict[str, Any]:
        """Perform comprehensive content analysis"""
        result = {
            'statistics': self._get_statistics(content),
            'extracted_data': self._extract_data(content),
            'sentiment': self._analyze_sentiment(content),
            'patterns': self._find_patterns(content),
            'hashes': self._generate_hashes(content),
            'keywords': self._extract_keywords(content)
        }
        return result
    
    def _get_statistics(self, content: str) -> Dict[str, int]:
        """Get basic content statistics"""
        lines = content.splitlines()
        words = content.split()
        
        return {
            'total_lines': len(lines),
            'total_words': len(words),
            'total_chars': len(content),
            'unique_words': len(set(words)),
            'avg_line_length': len(content) / len(lines) if lines else 0
        }
    
    def _extract_data(self, content: str) -> Dict[str, List[str]]:
        """Extract various types of data using patterns"""
        results = {}
        
        for data_type, pattern in self.patterns.items():
            matches = re.findall(pattern, content)
            if matches:
                results[data_type] = list(set(matches))  # Remove duplicates
        
        return results
    
    def _analyze_sentiment(self, content: str) -> Dict[str, float]:
        """Basic sentiment analysis"""
        # This is a simple implementation - could be enhanced with ML
        positive_words = {'good', 'great', 'excellent', 'positive', 'success', 'happy'}
        negative_words = {'bad', 'poor', 'negative', 'failure', 'error', 'issue'}
        
        words = content.lower().split()
        total_words = len(words)
        
        if total_words == 0:
            return {'sentiment_score': 0.0}
            
        positive_count = sum(1 for word in words if word in positive_words)
        negative_count = sum(1 for word in words if word in negative_words)
        
        sentiment_score = (positive_count - negative_count) / total_words
        
        return {
            'sentiment_score': sentiment_score,
            'positive_words': positive_count,
            'negative_words': negative_count
        }
    
    def _find_patterns(self, content: str) -> Dict[str, List[str]]:
        """Find common patterns and sequences"""
        lines = content.splitlines()
        patterns = {
            'repeated_lines': self._find_repeated_lines(lines),
            'common_prefixes': self._find_common_prefixes(lines),
            'common_suffixes': self._find_common_suffixes(lines),
            'numbered_lines': self._find_numbered_lines(lines)
        }
        return patterns
    
    def _find_repeated_lines(self, lines: List[str]) -> List[Tuple[str, int]]:
        """Find lines that appear multiple times"""
        counter = Counter(lines)
        return [(line, count) for line, count in counter.most_common(10) if count > 1]
    
    def _find_common_prefixes(self, lines: List[str]) -> List[Tuple[str, int]]:
        """Find common line prefixes"""
        prefixes = [line.split()[0] for line in lines if line.strip()]
        return Counter(prefixes).most_common(5)
    
    def _find_common_suffixes(self, lines: List[str]) -> List[Tuple[str, int]]:
        """Find common line suffixes"""
        suffixes = [line.split()[-1] for line in lines if line.strip()]
        return Counter(suffixes).most_common(5)
    
    def _find_numbered_lines(self, lines: List[str]) -> List[str]:
        """Find lines that start with numbers"""
        return [line for line in lines if re.match(r'^\d+', line)]
    
    def _generate_hashes(self, content: str) -> Dict[str, str]:
        """Generate various hashes of the content"""
        content_bytes = content.encode('utf-8')
        return {
            'md5': hashlib.md5(content_bytes).hexdigest(),
            'sha1': hashlib.sha1(content_bytes).hexdigest(),
            'sha256': hashlib.sha256(content_bytes).hexdigest()
        }
    
    def _extract_keywords(self, content: str) -> List[Tuple[str, int]]:
        """Extract potential keywords based on frequency"""
        # Remove common words
        common_words = {'the', 'be', 'to', 'of', 'and', 'a', 'in', 'that', 'have'}
        words = [word.lower() for word in re.findall(r'\w+', content)
                if word.lower() not in common_words and len(word) > 3]
        
        return Counter(words).most_common(10)
    
    def generate_report(self, analysis_result: Dict[str, Any]) -> str:
        """Generate a formatted analysis report"""
        report = []
        
        # Basic Statistics
        stats = analysis_result['statistics']
        report.append("=== Content Statistics ===")
        report.append(f"Total Lines: {stats['total_lines']}")
        report.append(f"Total Words: {stats['total_words']}")
        report.append(f"Total Characters: {stats['total_chars']}")
        report.append(f"Unique Words: {stats['unique_words']}")
        report.append(f"Average Line Length: {stats['avg_line_length']:.2f}")
        report.append("")
        
        # Extracted Data
        data = analysis_result['extracted_data']
        report.append("=== Extracted Data ===")
        for data_type, items in data.items():
            report.append(f"{data_type.title()}: {len(items)} found")
            for item in items[:5]:  # Show first 5 items
                report.append(f"  - {item}")
            if len(items) > 5:
                report.append(f"  ... and {len(items) - 5} more")
        report.append("")
        
        # Sentiment Analysis
        sentiment = analysis_result['sentiment']
        report.append("=== Sentiment Analysis ===")
        report.append(f"Sentiment Score: {sentiment['sentiment_score']:.2f}")
        if 'positive_words' in sentiment:
            report.append(f"Positive Words: {sentiment['positive_words']}")
            report.append(f"Negative Words: {sentiment['negative_words']}")
        report.append("")
        
        # Patterns
        patterns = analysis_result['patterns']
        report.append("=== Common Patterns ===")
        if patterns['repeated_lines']:
            report.append("Most Repeated Lines:")
            for line, count in patterns['repeated_lines'][:3]:
                report.append(f"  - '{line[:50]}...' ({count} times)")
        report.append("")
        
        # Hashes
        hashes = analysis_result['hashes']
        report.append("=== Content Hashes ===")
        for hash_type, hash_value in hashes.items():
            report.append(f"{hash_type.upper()}: {hash_value}")
        report.append("")
        
        # Keywords
        keywords = analysis_result['keywords']
        report.append("=== Top Keywords ===")
        for word, count in keywords:
            report.append(f"  - {word}: {count} occurrences")
            
        return "\n".join(report)
