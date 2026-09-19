import React from 'react';
import BobAssistantPanel from '../components/bob/BobAssistantPanel';

export default function BobPage() {
  return (
    <div className="h-[calc(100vh-8.5rem)] max-w-[1400px] mx-auto pb-4">
      <BobAssistantPanel isDedicatedPage={true} />
    </div>
  );
}