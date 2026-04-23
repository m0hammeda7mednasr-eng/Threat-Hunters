import { memo } from 'react';
import './AmbientScene.css';

function AmbientScene({ className = '', tone = 'primary', size = 'md' }) {
  const classes = ['ambient-scene', `ambient-scene--${tone}`, `ambient-scene--${size}`, className]
    .filter(Boolean)
    .join(' ');

  return (
    <div className={classes} aria-hidden="true">
      <span className="ambient-scene__halo" />
      <span className="ambient-scene__plane ambient-scene__plane--back" />
      <span className="ambient-scene__plane ambient-scene__plane--front" />
      <span className="ambient-scene__ring ambient-scene__ring--outer" />
      <span className="ambient-scene__ring ambient-scene__ring--inner" />
      <span className="ambient-scene__beam ambient-scene__beam--left" />
      <span className="ambient-scene__beam ambient-scene__beam--right" />
      <span className="ambient-scene__satellite ambient-scene__satellite--one" />
      <span className="ambient-scene__satellite ambient-scene__satellite--two" />
      <span className="ambient-scene__core">
        <span className="ambient-scene__core-mark" />
      </span>
    </div>
  );
}

export default memo(AmbientScene);
