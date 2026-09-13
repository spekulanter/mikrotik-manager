# Vendored frontend dependencies

These files are served locally so application pages do not execute code or load
styles and fonts directly from third-party CDNs.

| Component | Version | Upstream source | License |
| --- | --- | --- | --- |
| Tailwind CSS Play CDN runtime | 3.4.17 | `cdn.tailwindcss.com/3.4.17` | MIT |
| Socket.IO client | 4.4.1, 4.7.2 | cdnjs | MIT |
| Chart.js | 4.5.1 | jsDelivr/npm | MIT |
| date-fns | 2.29.3 | jsDelivr/npm | MIT |
| chartjs-adapter-date-fns | 2.0.0 | jsDelivr/npm | MIT |
| Flatpickr | 4.6.13 | jsDelivr/npm | MIT |
| Font Awesome Free | 6.0.0, 6.4.2 | cdnjs | Icons: CC BY 4.0; fonts: SIL OFL 1.1; code: MIT |
| Inter | v20 font files | Google Fonts | SIL OFL 1.1 |

Do not replace these files with unversioned CDN URLs. When upgrading a library,
update its versioned filename and every HTML reference in the same change, then
run the frontend smoke tests.
