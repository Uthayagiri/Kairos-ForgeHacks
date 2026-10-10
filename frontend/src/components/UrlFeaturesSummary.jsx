import React from 'react';
import { Lock, Unlock, Hash, Layers, AlertCircle, CheckCircle, Server, FileText } from 'lucide-react';

export default function UrlFeaturesSummary({ summary = {} }) {
  if (!summary || Object.keys(summary).length === 0) {
    return null;
  }

  const items = [
    {
      label: 'Protocol / Security',
      value: summary.uses_https ? 'HTTPS (Encrypted)' : 'HTTP (Plaintext)',
      isPositive: summary.uses_https,
      icon: summary.uses_https ? Lock : Unlock,
    },
    {
      label: 'Host Structure',
      value: summary.has_ip_address ? 'Raw IP Host' : 'Named Domain',
      isPositive: !summary.has_ip_address,
      icon: Server,
    },
    {
      label: 'Subdomain Count',
      value: `${summary.num_subdomains || 0} subdomains`,
      isPositive: (summary.num_subdomains || 0) < 3,
      icon: Layers,
    },
    {
      label: 'Domain Length',
      value: `${summary.domain_length || 0} chars`,
      isPositive: (summary.domain_length || 0) < 30,
      icon: Hash,
    },
    {
      label: 'Path Depth',
      value: `${summary.path_length || 0} path chars`,
      isPositive: true,
      icon: FileText,
    },
    {
      label: 'TLD Classification',
      value: summary.has_suspicious_tld ? 'Suspicious TLD' : 'Standard TLD',
      isPositive: !summary.has_suspicious_tld,
      icon: summary.has_suspicious_tld ? AlertCircle : CheckCircle,
    },
  ];

  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 gap-2.5">
      {items.map((item, idx) => {
        const Icon = item.icon;
        return (
          <div
            key={idx}
            className="p-3 rounded-xl bg-cyber-900/60 border border-slate-800/80 flex flex-col justify-between"
          >
            <div className="flex items-center justify-between text-[11px] text-slate-400 mb-1">
              <span>{item.label}</span>
              <Icon className={`w-3.5 h-3.5 ${item.isPositive ? 'text-emerald-400' : 'text-rose-400'}`} />
            </div>
            <div className={`text-xs sm:text-sm font-mono font-medium ${item.isPositive ? 'text-slate-200' : 'text-rose-300'}`}>
              {item.value}
            </div>
          </div>
        );
      })}
    </div>
  );
}
