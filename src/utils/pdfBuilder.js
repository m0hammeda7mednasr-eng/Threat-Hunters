const PAGE_WIDTH = 612;
const PAGE_HEIGHT = 792;
const MARGIN_X = 48;
const TOP_Y = 734;
const BOTTOM_Y = 58;

const escapePdfText = (value) => String(value ?? '')
  .replace(/[^\x20-\x7E]/g, '')
  .replace(/\\/g, '\\\\')
  .replace(/\(/g, '\\(')
  .replace(/\)/g, '\\)');

const hexToRgb = (hex) => {
  const normalized = String(hex || '#ffffff').replace('#', '');
  const value = normalized.length === 3
    ? normalized.split('').map((char) => char + char).join('')
    : normalized.padEnd(6, '0').slice(0, 6);

  return [
    parseInt(value.slice(0, 2), 16) / 255,
    parseInt(value.slice(2, 4), 16) / 255,
    parseInt(value.slice(4, 6), 16) / 255,
  ];
};

const rgb = (hex, mode = 'rg') => `${hexToRgb(hex).map((item) => item.toFixed(3)).join(' ')} ${mode}`;

const wrapText = (value, maxLength = 84) => {
  const words = String(value || '').split(/\s+/).filter(Boolean);
  const lines = [];
  let current = '';

  for (const word of words) {
    const next = current ? `${current} ${word}` : word;
    if (next.length > maxLength && current) {
      lines.push(current);
      current = word;
      continue;
    }
    current = next;
  }

  if (current) {
    lines.push(current);
  }

  return lines.length ? lines : [''];
};

const textCommand = (text, x, y, options = {}) => {
  const {
    font = 'F1',
    size = 11,
    color = '#e7e9ff',
  } = options;

  return [
    'BT',
    rgb(color, 'rg'),
    `/${font} ${size} Tf`,
    `${x} ${y} Td (${escapePdfText(text)}) Tj`,
    'ET',
  ].join('\n');
};

const rectCommand = (x, y, width, height, fill, stroke = null) => {
  const commands = ['q', rgb(fill, 'rg')];
  if (stroke) {
    commands.push(rgb(stroke, 'RG'));
    commands.push(`${x} ${y} ${width} ${height} re B`);
  } else {
    commands.push(`${x} ${y} ${width} ${height} re f`);
  }
  commands.push('Q');
  return commands.join('\n');
};

const shieldLogoCommand = (x, y) => [
  'q',
  rgb('#8b7cff', 'rg'),
  `${x} ${y} 34 34 re f`,
  rgb('#ffffff', 'RG'),
  '2 w',
  `${x + 17} ${y + 27} m`,
  `${x + 8} ${y + 23} l`,
  `${x + 8} ${y + 15} l`,
  `${x + 17} ${y + 7} l`,
  `${x + 26} ${y + 15} l`,
  `${x + 26} ${y + 23} l`,
  'h S',
  `${x + 13} ${y + 17} m`,
  `${x + 16} ${y + 13} l`,
  `${x + 22} ${y + 20} l`,
  'S',
  'Q',
].join('\n');

const headerCommands = ({ title, subtitle, eyebrow, generatedAt }) => [
  rectCommand(0, 680, PAGE_WIDTH, 112, '#080a1a'),
  rectCommand(0, 674, PAGE_WIDTH, 6, '#8b7cff'),
  rectCommand(426, 704, 138, 42, '#121633', '#2f386b'),
  shieldLogoCommand(MARGIN_X, 720),
  textCommand('Threat Hunters', 92, 742, { font: 'F2', size: 17, color: '#ffffff' }),
  textCommand(eyebrow || 'Security Report', 92, 724, { size: 9, color: '#9ba8ff' }),
  textCommand(generatedAt || new Date().toLocaleString('en-US'), 442, 729, { size: 9, color: '#d8dcff' }),
  textCommand('Generated', 442, 742, { font: 'F2', size: 10, color: '#ffffff' }),
  textCommand(title, MARGIN_X, 646, { font: 'F2', size: 22, color: '#0d1228' }),
  ...wrapText(subtitle, 92).slice(0, 2).map((line, index) => (
    textCommand(line, MARGIN_X, 626 - index * 15, { size: 11, color: '#4b5677' })
  )),
].join('\n');

const footerCommands = (pageNumber) => [
  rectCommand(MARGIN_X, 36, PAGE_WIDTH - MARGIN_X * 2, 1, '#d9def8'),
  textCommand('Threat Hunters Security Intelligence', MARGIN_X, 22, { size: 9, color: '#56617d' }),
  textCommand(`Page ${pageNumber}`, PAGE_WIDTH - 86, 22, { size: 9, color: '#56617d' }),
].join('\n');

const createPage = (pageNumber, bodyCommands, headerOptions = {}) => [
  rectCommand(0, 0, PAGE_WIDTH, PAGE_HEIGHT, '#f6f8ff'),
  headerCommands(headerOptions),
  bodyCommands.join('\n'),
  footerCommands(pageNumber),
].join('\n');

export const buildBrandedPdfBlob = ({
  title,
  subtitle,
  eyebrow = 'Security Report',
  generatedAt,
  metrics = [],
  sections = [],
}) => {
  const pages = [];
  let y = TOP_Y - 176;
  let body = [];

  const pushPage = () => {
    pages.push(createPage(pages.length + 1, body, { title, subtitle, eyebrow, generatedAt }));
    body = [];
    y = TOP_Y - 176;
  };

  const ensureSpace = (height) => {
    if (y - height < BOTTOM_Y) {
      pushPage();
    }
  };

  const safeMetrics = metrics.filter(Boolean).slice(0, 4);
  if (safeMetrics.length) {
    const cardWidth = 122;
    safeMetrics.forEach((metric, index) => {
      const x = MARGIN_X + index * (cardWidth + 12);
      body.push(rectCommand(x, y - 62, cardWidth, 54, metric.fill || '#ffffff', metric.stroke || '#d9def8'));
      body.push(textCommand(metric.label, x + 12, y - 28, { size: 8, color: metric.labelColor || '#66708d' }));
      body.push(textCommand(metric.value, x + 12, y - 49, { font: 'F2', size: 17, color: metric.valueColor || '#161b33' }));
    });
    y -= 92;
  }

  sections.forEach((section, sectionIndex) => {
    const bullets = Array.isArray(section.items) ? section.items : [];
    const paragraphLines = wrapText(section.body || '', 92);
    const estimatedHeight = 36 + paragraphLines.length * 14 + bullets.length * 28;
    ensureSpace(estimatedHeight);

    body.push(rectCommand(MARGIN_X, y - 2, 5, 24, section.accent || '#8b7cff'));
    body.push(textCommand(section.title || `Section ${sectionIndex + 1}`, MARGIN_X + 14, y + 2, {
      font: 'F2',
      size: 15,
      color: '#151a32',
    }));
    y -= 24;

    if (section.body) {
      paragraphLines.forEach((line) => {
        ensureSpace(18);
        body.push(textCommand(line, MARGIN_X, y, { size: 10.5, color: '#4a5572' }));
        y -= 14;
      });
      y -= 6;
    }

    bullets.forEach((item) => {
      const lines = wrapText(item, 84);
      ensureSpace(22 + lines.length * 13);
      body.push(rectCommand(MARGIN_X, y - 5, 9, 9, section.accent || '#8b7cff'));
      lines.forEach((line, lineIndex) => {
        body.push(textCommand(line, MARGIN_X + 18, y - lineIndex * 13, { size: 10.5, color: '#303a57' }));
      });
      y -= 16 + (lines.length - 1) * 13;
    });

    y -= 14;
  });

  if (!pages.length || body.length) {
    pushPage();
  }

  const objects = [
    `1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n`,
    `2 0 obj\n<< /Type /Pages /Kids [${pages.map((_, index) => `${3 + index} 0 R`).join(' ')}] /Count ${pages.length} >>\nendobj\n`,
    ...pages.map((page, index) => {
      const pageObjectId = 3 + index;
      const contentObjectId = 3 + pages.length + index;
      return `${pageObjectId} 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${PAGE_WIDTH} ${PAGE_HEIGHT}] /Resources << /Font << /F1 ${3 + pages.length * 2} 0 R /F2 ${4 + pages.length * 2} 0 R >> >> /Contents ${contentObjectId} 0 R >>\nendobj\n`;
    }),
    ...pages.map((page, index) => {
      const contentObjectId = 3 + pages.length + index;
      return `${contentObjectId} 0 obj\n<< /Length ${page.length} >>\nstream\n${page}\nendstream\nendobj\n`;
    }),
    `${3 + pages.length * 2} 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n`,
    `${4 + pages.length * 2} 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>\nendobj\n`,
  ];

  let pdf = '%PDF-1.4\n';
  const offsets = [0];
  objects.forEach((object) => {
    offsets.push(pdf.length);
    pdf += object;
  });

  const xrefOffset = pdf.length;
  pdf += `xref\n0 ${objects.length + 1}\n`;
  pdf += '0000000000 65535 f \n';
  for (let index = 1; index <= objects.length; index += 1) {
    pdf += `${String(offsets[index]).padStart(10, '0')} 00000 n \n`;
  }
  pdf += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefOffset}\n%%EOF`;

  return new Blob([pdf], { type: 'application/pdf' });
};

export const downloadPdfBlob = (blob, filename) => {
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
};
