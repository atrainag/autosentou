"""
PathAnalyzer - Intelligent Path Analysis
Analyzes discovered web paths to identify vulnerabilities and risky patterns
"""
import re
import logging
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse, parse_qs
from pathlib import Path

logger = logging.getLogger(__name__)


class PathAnalyzer:
    """
    Analyzes discovered web paths using pattern matching and knowledge base.
    Identifies potentially vulnerable paths, sensitive files, and attack surfaces.
    """

    # Built-in vulnerable path patterns (fallback if knowledge base unavailable)
    BUILTIN_PATTERNS = {
        'admin': {
            'patterns': ['/admin', '/administrator', '/manager', '/cpanel', '/phpmyadmin', '/wp-admin'],
            'risk': 'high',
            'category': 'Admin Panel',
            'description': 'Administrative interfaces that may expose privileged functionality'
        },
        'config': {
            'patterns': ['.env', 'config.php', 'configuration.php', 'web.config', 'database.yml', 'settings.py'],
            'risk': 'critical',
            'category': 'Configuration File',
            'description': 'Configuration files that may contain sensitive credentials'
        },
        'backup': {
            'patterns': ['.bak', '.backup', '.old', '.sql', '.tar.gz', '.zip', 'backup/', 'dump.sql'],
            'risk': 'high',
            'category': 'Backup File',
            'description': 'Backup files that may expose source code or database dumps'
        },
        'api': {
            'patterns': ['/api/', '/rest/', '/graphql', '/v1/', '/v2/', '/swagger', '/openapi'],
            'risk': 'medium',
            'category': 'API Endpoint',
            'description': 'API endpoints that may have insufficient authentication or input validation'
        },
        'upload': {
            'patterns': ['/upload', '/uploads/', '/files/', '/media/', '/attachments/'],
            'risk': 'high',
            'category': 'File Upload',
            'description': 'File upload functionality vulnerable to unrestricted file upload'
        },
        'debug': {
            'patterns': ['/debug', '/test', '/phpinfo.php', '/info.php', '/trace', '/_profiler'],
            'risk': 'high',
            'category': 'Debug/Test',
            'description': 'Debug or test pages that expose sensitive system information'
        },
        'auth': {
            'patterns': ['/login', '/signin', '/auth/', '/sso/', '/oauth/', '/register', '/signup'],
            'risk': 'medium',
            'category': 'Authentication',
            'description': 'Authentication endpoints vulnerable to enumeration or bypass'
        },
        'git': {
            'patterns': ['/.git/', '/.svn/', '/.hg/', '/.gitignore'],
            'risk': 'critical',
            'category': 'Version Control',
            'description': 'Exposed version control directories containing source code'
        },
        'database': {
            'patterns': ['/db/', '/database/', '/mysql/', '/postgres/', '/mongodb/'],
            'risk': 'critical',
            'category': 'Database Access',
            'description': 'Direct database access interfaces'
        },
        'logs': {
            'patterns': ['/logs/', '/log/', '.log', 'error.log', 'access.log', 'debug.log'],
            'risk': 'medium',
            'category': 'Log Files',
            'description': 'Log files that may contain sensitive information or error details'
        }
    }

    # HTTP methods for testing
    HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']

    # File extensions by risk level
    RISKY_EXTENSIONS = {
        'critical': ['.env', '.sql', '.db', '.sqlite', '.bak', '.config', '.key', '.pem'],
        'high': ['.zip', '.tar.gz', '.rar', '.backup', '.old', '.yml', '.yaml', '.json'],
        'medium': ['.log', '.txt', '.xml', '.php~', '.swp', '.inc']
    }

    def __init__(self, knowledge_manager=None):
        """
        Initialize PathAnalyzer.

        Args:
            knowledge_manager: Optional KnowledgeManager instance for RAG-enhanced analysis
        """
        self.knowledge_manager = knowledge_manager
        logger.info("PathAnalyzer initialized")

    def analyze_paths(
        self,
        paths: List[str],
        base_url: str,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Analyze multiple paths and categorize by risk.

        Args:
            paths: List of discovered paths/URLs
            base_url: Base URL of the target
            context: Additional context (technologies, services, etc.)

        Returns:
            Analysis results with risk categorization
        """
        logger.info(f"Analyzing {len(paths)} paths from {base_url}")

        results = {
            'total_paths': len(paths),
            'base_url': base_url,
            'risk_summary': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            },
            'findings': [],
            'categories': {},
            'recommended_tests': []
        }

        # Analyze each path
        for path in paths:
            analysis = self._analyze_single_path(path, base_url, context)

            if analysis:
                results['findings'].append(analysis)

                # Update risk summary
                risk = analysis.get('risk', 'low')
                if risk in results['risk_summary']:
                    results['risk_summary'][risk] += 1

                # Update categories
                category = analysis.get('category', 'Unknown')
                if category not in results['categories']:
                    results['categories'][category] = []
                results['categories'][category].append(path)

        # Sort findings by risk (critical first)
        risk_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        results['findings'].sort(key=lambda x: risk_order.get(x.get('risk', 'low'), 4))

        # Generate recommended tests
        results['recommended_tests'] = self._generate_test_recommendations(results)

        logger.info(f"Analysis complete: {results['risk_summary']['critical']} critical, "
                   f"{results['risk_summary']['high']} high risk findings")

        return results

    def _analyze_single_path(
        self,
        path: str,
        base_url: str,
        context: Optional[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        """
        Analyze a single path for vulnerabilities.

        Args:
            path: Path or URL to analyze
            base_url: Base URL
            context: Additional context

        Returns:
            Analysis result or None if path is not interesting
        """
        # Extract clean path
        clean_path = self._extract_path(path)

        # Check against knowledge base first (if available)
        kb_matches = []
        if self.knowledge_manager:
            try:
                kb_matches = self.knowledge_manager.check_path_vulnerability(clean_path)
            except Exception as e:
                logger.debug(f"Knowledge base check failed: {e}")

        # If knowledge base found matches, use those
        if kb_matches:
            # Use the highest-risk match
            best_match = kb_matches[0]
            return {
                'path': path,
                'clean_path': clean_path,
                'risk': best_match.get('risk', 'medium'),
                'category': best_match.get('category', 'Unknown'),
                'description': best_match.get('description', ''),
                'attack_type': best_match.get('attack_type', ''),
                'testing_method': best_match.get('testing_method', ''),
                'similarity_score': best_match.get('similarity_score', 0),
                'source': 'knowledge_base'
            }

        # Fallback to built-in pattern matching
        pattern_match = self._check_builtin_patterns(clean_path)
        if pattern_match:
            return {
                'path': path,
                'clean_path': clean_path,
                'risk': pattern_match['risk'],
                'category': pattern_match['category'],
                'description': pattern_match['description'],
                'pattern_matched': pattern_match['pattern_matched'],
                'source': 'builtin_patterns',
                **self._extract_path_features(clean_path)
            }

        # Check file extension risk
        extension_risk = self._check_extension_risk(clean_path)
        if extension_risk:
            return {
                'path': path,
                'clean_path': clean_path,
                'risk': extension_risk['risk'],
                'category': 'Sensitive File',
                'description': f"File with {extension_risk['risk']} risk extension: {extension_risk['extension']}",
                'extension': extension_risk['extension'],
                'source': 'extension_analysis',
                **self._extract_path_features(clean_path)
            }

        # Check for interesting parameters
        if '?' in path:
            param_analysis = self._analyze_parameters(path)
            if param_analysis.get('risk') != 'low':
                return {
                    'path': path,
                    'clean_path': clean_path,
                    **param_analysis,
                    'source': 'parameter_analysis'
                }

        return None

    def _extract_path(self, url: str) -> str:
        """Extract clean path from URL."""
        try:
            parsed = urlparse(url)
            return parsed.path or '/'
        except:
            return url

    def _check_builtin_patterns(self, path: str) -> Optional[Dict[str, Any]]:
        """
        Check path against built-in patterns.

        Args:
            path: Path to check

        Returns:
            Match information or None
        """
        path_lower = path.lower()

        for pattern_group, data in self.BUILTIN_PATTERNS.items():
            for pattern in data['patterns']:
                if pattern.lower() in path_lower:
                    return {
                        'risk': data['risk'],
                        'category': data['category'],
                        'description': data['description'],
                        'pattern_matched': pattern
                    }

        return None

    def _check_extension_risk(self, path: str) -> Optional[Dict[str, Any]]:
        """
        Check if path has a risky file extension.

        Args:
            path: Path to check

        Returns:
            Risk information or None
        """
        path_lower = path.lower()

        for risk_level, extensions in self.RISKY_EXTENSIONS.items():
            for ext in extensions:
                if path_lower.endswith(ext):
                    return {
                        'risk': risk_level,
                        'extension': ext
                    }

        return None

    def _analyze_parameters(self, url: str) -> Dict[str, Any]:
        """
        Analyze URL parameters for potential vulnerabilities.

        Args:
            url: URL with parameters

        Returns:
            Analysis result
        """
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            if not params:
                return {'risk': 'low', 'category': 'URL with parameters'}

            # Check for suspicious parameter names
            suspicious_params = {
                'id': ['sqli', 'idor'],
                'page': ['lfi', 'path_traversal'],
                'file': ['lfi', 'path_traversal', 'unrestricted_file_access'],
                'url': ['ssrf', 'open_redirect'],
                'redirect': ['open_redirect'],
                'callback': ['ssrf', 'open_redirect'],
                'path': ['path_traversal', 'lfi'],
                'include': ['lfi', 'rfi'],
                'template': ['ssti', 'lfi'],
                'query': ['sqli', 'nosql_injection'],
                'search': ['sqli', 'xss'],
                'cmd': ['command_injection', 'rce'],
                'exec': ['command_injection', 'rce']
            }

            risky_params = []
            attack_vectors = []

            for param_name in params.keys():
                param_lower = param_name.lower()
                for pattern, vectors in suspicious_params.items():
                    if pattern in param_lower:
                        risky_params.append(param_name)
                        attack_vectors.extend(vectors)
                        break

            if risky_params:
                return {
                    'risk': 'high',
                    'category': 'Risky Parameters',
                    'description': f"URL contains potentially vulnerable parameters: {', '.join(risky_params)}",
                    'risky_parameters': risky_params,
                    'potential_attack_vectors': list(set(attack_vectors)),
                    'parameter_count': len(params)
                }

            return {
                'risk': 'medium',
                'category': 'URL with parameters',
                'description': f"URL contains {len(params)} parameters that should be tested",
                'parameter_count': len(params),
                'parameters': list(params.keys())
            }

        except Exception as e:
            logger.debug(f"Error analyzing parameters: {e}")
            return {'risk': 'low', 'category': 'URL with parameters'}

    def _extract_path_features(self, path: str) -> Dict[str, Any]:
        """
        Extract additional features from path.

        Args:
            path: Path to analyze

        Returns:
            Feature dictionary
        """
        features = {}

        # Check for dynamic indicators
        if any(indicator in path.lower() for indicator in ['?', '=', '&', '.php', '.asp', '.jsp']):
            features['is_dynamic'] = True
        else:
            features['is_dynamic'] = False

        # Check for depth
        features['depth'] = path.count('/')

        # Check for file vs directory
        if path.endswith('/'):
            features['type'] = 'directory'
        elif '.' in path.split('/')[-1]:
            features['type'] = 'file'
        else:
            features['type'] = 'unknown'

        return features

    def _generate_test_recommendations(self, analysis_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Generate testing recommendations based on analysis.

        Args:
            analysis_results: Overall analysis results

        Returns:
            List of recommended tests
        """
        recommendations = []
        categories = analysis_results.get('categories', {})

        # Admin panel testing
        if 'Admin Panel' in categories:
            recommendations.append({
                'test_type': 'Authentication Testing',
                'priority': 'high',
                'description': 'Test admin panels for default credentials, weak passwords, and authentication bypass',
                'paths': categories['Admin Panel']
            })

        # API testing
        if 'API Endpoint' in categories:
            recommendations.append({
                'test_type': 'API Security Testing',
                'priority': 'high',
                'description': 'Test API endpoints for authentication, authorization, and input validation issues',
                'paths': categories['API Endpoint'],
                'methods': self.HTTP_METHODS
            })

        # File upload testing
        if 'File Upload' in categories:
            recommendations.append({
                'test_type': 'File Upload Testing',
                'priority': 'critical',
                'description': 'Test for unrestricted file upload vulnerabilities (RCE)',
                'paths': categories['File Upload']
            })

        # Configuration file access
        if 'Configuration File' in categories:
            recommendations.append({
                'test_type': 'Sensitive File Access',
                'priority': 'critical',
                'description': 'Attempt to access configuration files to extract credentials',
                'paths': categories['Configuration File']
            })

        # Parameter testing
        if 'Risky Parameters' in categories:
            recommendations.append({
                'test_type': 'Injection Testing',
                'priority': 'high',
                'description': 'Test risky parameters for SQL injection, XSS, command injection, etc.',
                'paths': categories['Risky Parameters']
            })

        # Version control exposure
        if 'Version Control' in categories:
            recommendations.append({
                'test_type': 'Source Code Disclosure',
                'priority': 'critical',
                'description': 'Download exposed version control directories to extract source code',
                'paths': categories['Version Control']
            })

        return recommendations

    def get_attack_surface_summary(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate attack surface summary from analysis.

        Args:
            analysis_results: Path analysis results

        Returns:
            Attack surface summary
        """
        findings = analysis_results.get('findings', [])
        categories = analysis_results.get('categories', {})

        # Calculate attack surface metrics
        attack_surface = {
            'total_findings': len(findings),
            'risk_distribution': analysis_results.get('risk_summary', {}),
            'category_distribution': {k: len(v) for k, v in categories.items()},
            'top_risks': findings[:10],  # Top 10 risky paths
            'attack_vectors': [],
            'priority_targets': []
        }

        # Identify attack vectors
        attack_vectors = set()
        for finding in findings:
            if finding.get('potential_attack_vectors'):
                attack_vectors.update(finding['potential_attack_vectors'])
            if finding.get('attack_type'):
                attack_vectors.add(finding['attack_type'])

        attack_surface['attack_vectors'] = list(attack_vectors)

        # Identify priority targets (critical + high risk)
        priority_targets = [
            f for f in findings
            if f.get('risk') in ['critical', 'high']
        ]
        attack_surface['priority_targets'] = priority_targets[:15]

        return attack_surface
