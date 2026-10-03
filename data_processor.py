import pandas as pd
import numpy as np
import os
import json
import random
from sklearn.utils import resample

class DataProcessor:
    def __init__(self):
        self.processed_data = None
        self.feature_names = None
    
    def process_csv(self, csv_path, sample_size=None):
        """
        Process CSV file and return URLs and labels
        Expected CSV columns: 'url' and 'label'
        """
        if not os.path.exists(csv_path):
            raise FileNotFoundError(f"CSV file not found: {csv_path}")
        
        try:
            # Try different encodings
            encodings = ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']
            df = None
            
            for encoding in encodings:
                try:
                    df = pd.read_csv(csv_path, encoding=encoding, on_bad_lines='skip')
                    print(f"✅ Loaded with encoding: {encoding}")
                    break
                except UnicodeDecodeError:
                    continue
            
            if df is None:
                raise ValueError("Could not read CSV with any encoding")
            
            print(f"📊 Loaded {len(df)} records from {csv_path}")
            print(f"📊 Columns: {df.columns.tolist()}")
            
            # Check for required columns (case insensitive)
            df.columns = df.columns.str.strip()
            
            url_col = None
            label_col = None
            
            for col in df.columns:
                col_lower = col.lower()
                if 'url' in col_lower or 'domain' in col_lower or 'link' in col_lower:
                    url_col = col
                if 'label' in col_lower or 'class' in col_lower or 'target' in col_lower or 'phishing' in col_lower:
                    label_col = col
            
            if url_col is None:
                raise ValueError("CSV must have a column containing 'url', 'domain', or 'link'")
            
            if label_col is None:
                raise ValueError("CSV must have a column containing 'label', 'class', 'target', or 'phishing'")
            
            print(f"🎯 Using URL column: {url_col}")
            print(f"🎯 Using Label column: {label_col}")
            
            # Clean data
            df = df.dropna(subset=[url_col, label_col])
            
            # Convert labels to numeric
            if df[label_col].dtype == 'object':
                # Try to map string labels to numeric
                unique_labels = df[label_col].unique()
                label_map = {}
                for label in unique_labels:
                    label_lower = str(label).lower()
                    if label_lower in ['phishing', '1', 'phish', 'malicious', 'spam', 'fake', 'bad']:
                        label_map[label] = 1
                    elif label_lower in ['legitimate', '0', 'legit', 'safe', 'good', 'benign', 'real']:
                        label_map[label] = 0
                    else:
                        # Try to convert to numeric
                        try:
                            label_map[label] = int(label)
                        except:
                            label_map[label] = 0
                
                df[label_col] = df[label_col].map(label_map)
            
            # Ensure labels are 0 or 1
            df[label_col] = df[label_col].apply(lambda x: 1 if x == 1 else 0)
            
            # Remove empty URLs
            df = df[df[url_col].str.strip() != '']
            
            # Sample if needed
            if sample_size and len(df) > sample_size:
                df = df.sample(sample_size, random_state=42)
                print(f"📊 Using {sample_size} samples")
            
            # Convert to lists
            urls = df[url_col].tolist()
            labels = df[label_col].tolist()
            
            # Add protocol to URLs that don't have it
            urls = self._normalize_urls(urls)
            
            print(f"📊 Processed {len(urls)} URLs")
            print(f"📊 Phishing: {sum(labels)} ({sum(labels)/len(labels)*100:.1f}%)")
            print(f"📊 Legitimate: {len(labels)-sum(labels)} ({(len(labels)-sum(labels))/len(labels)*100:.1f}%)")
            
            return urls, labels
            
        except Exception as e:
            print(f"⚠️ Error processing CSV: {e}")
            import traceback
            traceback.print_exc()
            return None, None
    
    def _normalize_urls(self, urls):
        """Add protocol to URLs that don't have it"""
        normalized = []
        for url in urls:
            url = str(url).strip()
            if not url.startswith(('http://', 'https://')):
                if '.' in url:
                    url = 'http://' + url
            normalized.append(url)
        return normalized
    
    def balance_dataset(self, urls, labels):
        """
        Balance dataset by oversampling the minority class
        """
        if len(urls) != len(labels):
            raise ValueError("URLs and labels must have the same length")
        
        if len(urls) == 0:
            return [], []
        
        # Separate classes
        phishing = [(u, l) for u, l in zip(urls, labels) if l == 1]
        legitimate = [(u, l) for u, l in zip(urls, labels) if l == 0]
        
        print(f"📊 Before balancing - Phishing: {len(phishing)}, Legitimate: {len(legitimate)}")
        
        if len(phishing) == 0 or len(legitimate) == 0:
            print("⚠️ Only one class present in dataset")
            return urls, labels
        
        if len(phishing) < len(legitimate):
            # Oversample phishing class
            phishing_oversampled = resample(
                phishing, 
                replace=True, 
                n_samples=len(legitimate), 
                random_state=42
            )
            balanced = phishing_oversampled + legitimate
        else:
            # Oversample legitimate class
            legitimate_oversampled = resample(
                legitimate, 
                replace=True, 
                n_samples=len(phishing), 
                random_state=42
            )
            balanced = phishing + legitimate_oversampled
        
        # Shuffle
        random.shuffle(balanced)
        
        balanced_urls = [u for u, l in balanced]
        balanced_labels = [l for u, l in balanced]
        
        print(f"📊 After balancing - Phishing: {sum(balanced_labels)}, Legitimate: {len(balanced_labels) - sum(balanced_labels)}")
        
        return balanced_urls, balanced_labels
    
    def get_stats(self, csv_path):
        """
        Get CSV statistics without loading the entire file
        """
        if not os.path.exists(csv_path):
            return {'error': 'File not found'}
        
        try:
            # Try different encodings
            df = None
            for encoding in ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']:
                try:
                    df = pd.read_csv(csv_path, encoding=encoding, nrows=1000)
                    break
                except:
                    continue
            
            if df is None:
                return {'error': 'Could not read CSV file'}
            
            # Count total rows
            total_rows = 0
            for encoding in ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']:
                try:
                    with open(csv_path, 'r', encoding=encoding, errors='ignore') as f:
                        total_rows = sum(1 for _ in f) - 1
                    break
                except:
                    continue
            
            # Find URL and label columns
            url_col = None
            label_col = None
            
            for col in df.columns:
                col_lower = col.lower()
                if 'url' in col_lower or 'domain' in col_lower or 'link' in col_lower:
                    url_col = col
                if 'label' in col_lower or 'class' in col_lower or 'target' in col_lower or 'phishing' in col_lower:
                    label_col = col
            
            return {
                'total_rows': max(0, total_rows),
                'columns': df.columns.tolist(),
                'sample': df.head(3).to_dict('records'),
                'has_url': url_col is not None,
                'has_label': label_col is not None,
                'url_column': url_col,
                'label_column': label_col,
                'preview_urls': df[url_col].head(5).tolist() if url_col else [],
                'labels_present': df[label_col].nunique() if label_col else 0
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def create_sample_csv(self, output_path='data/sample_data.csv'):
        """
        Create a sample CSV file for testing
        """
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        # Sample phishing URLs
        phishing_urls = [
            "http://gogle.com",
            "http://paypall.com", 
            "https://secure-login-paypal.com",
            "http://bank-account-verify.tk",
            "https://google-security-verify.xyz",
            "http://amazon-account-update.com",
            "https://netflix-account-verify.ml",
            "http://apple-id-confirm.com",
            "https://microsoft-update.ga",
            "http://facebook-login-secure.com",
            "https://www.paypal.com.secure-login.tk",
            "http://accounts-google.com",
            "https://verify-identity.com",
            "http://security-check.biz",
            "https://login-helpdesk.com",
        ]
        
        # Sample legitimate URLs
        legitimate_urls = [
            "https://www.google.com",
            "https://www.youtube.com",
            "https://www.facebook.com",
            "https://www.amazon.com",
            "https://www.paypal.com",
            "https://www.microsoft.com",
            "https://www.apple.com",
            "https://www.github.com",
            "https://www.stackoverflow.com",
            "https://www.netflix.com",
            "https://www.twitter.com",
            "https://www.instagram.com",
            "https://www.linkedin.com",
            "https://www.reddit.com",
            "https://www.zoom.us",
            "https://slack.com",
            "https://notion.so",
            "https://deepseek.com",
            "https://openai.com",
            "https://claude.ai",
        ]
        
        # Create dataframe
        urls = phishing_urls + legitimate_urls
        labels = [1] * len(phishing_urls) + [0] * len(legitimate_urls)
        
        # Shuffle
        combined = list(zip(urls, labels))
        random.shuffle(combined)
        urls, labels = zip(*combined)
        
        df = pd.DataFrame({
            'url': urls,
            'label': labels
        })
        
        df.to_csv(output_path, index=False)
        print(f"✅ Sample CSV created: {output_path}")
        print(f"📊 Total rows: {len(df)}")
        print(f"📊 Phishing: {sum(labels)}")
        print(f"📊 Legitimate: {len(labels) - sum(labels)}")
        
        return output_path

    def merge_datasets(self, csv_files, output_path='data/merged_data.csv'):
        """
        Merge multiple CSV files into one
        """
        all_dfs = []
        
        for csv_file in csv_files:
            if os.path.exists(csv_file):
                try:
                    df = pd.read_csv(csv_file, encoding='utf-8', on_bad_lines='skip')
                    all_dfs.append(df)
                    print(f"📊 Loaded {len(df)} records from {csv_file}")
                except Exception as e:
                    print(f"⚠️ Error loading {csv_file}: {e}")
        
        if not all_dfs:
            return None
        
        merged_df = pd.concat(all_dfs, ignore_index=True)
        
        # Remove duplicates
        merged_df = merged_df.drop_duplicates(subset=['url'])
        
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        merged_df.to_csv(output_path, index=False)
        
        print(f"✅ Merged {len(merged_df)} unique records to {output_path}")
        return output_path