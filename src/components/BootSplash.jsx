import { memo } from 'react';
import './BootSplash.css';

const virusArms = Array.from({ length: 8 }, (_, index) => index);
const virusParticles = Array.from({ length: 14 }, (_, index) => index);

function BootSplash() {
  return (
    <div
      className="boot-splash"
      aria-label="Loading Threat Hunters"
      aria-live="polite"
      role="status"
    >
      <div className="boot-splash__backdrop" aria-hidden="true" />

      <div className="boot-splash__virus" aria-hidden="true">
        {virusArms.map((index) => (
          <span
            key={`arm-${index}`}
            className="boot-splash__virus-arm"
            style={{ '--arm-angle': `${index * 45}deg` }}
          />
        ))}

        <span className="boot-splash__virus-core">
          <span className="boot-splash__virus-core-ring" />
          <span className="boot-splash__virus-core-dot" />
        </span>

        {virusParticles.map((index) => (
          <span
            key={`particle-${index}`}
            className="boot-splash__particle"
            style={{
              '--particle-angle': `${index * 25}deg`,
              '--particle-delay': `${index * 55}ms`,
              '--particle-distance': `${56 + (index % 5) * 12}px`,
            }}
          />
        ))}
      </div>

      <div className="boot-splash__copy">
        <span className="boot-splash__eyebrow">Threat Hunters</span>
        <strong>Threat Hunters</strong>
        <p>Initializing threat intelligence and neutralizing live signatures.</p>
      </div>

      <div className="boot-splash__progress" aria-hidden="true">
        <span />
      </div>
    </div>
  );
}

export default memo(BootSplash);
