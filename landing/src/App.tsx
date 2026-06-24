import { lazy, Suspense } from 'react';

// Keep only the Navbar (if present) as a normal import – it's critical above the fold
import Navbar from './components/Navbar';   // if you have one, otherwise skip

// Lazy-load all other components (list all that are imported)
const Hero = lazy(() => import('./components/Hero'));
const FeaturesSection = lazy(() => import('./components/FeaturesSection'));
const StatsSection = lazy(() => import('./components/StatsSection'));
const CtaSection = lazy(() => import('./components/CtaSection'));
const BreachCards = lazy(() => import('./components/BreachCards'));
const ComparisonTable = lazy(() => import('./components/ComparisonTable'));
const DemoSection = lazy(() => import('./components/DemoSection'));
const Footer = lazy(() => import('./components/Footer'));
const InstallSection = lazy(() => import('./components/InstallSection'));
const InteractivePieChart = lazy(() => import('./components/InteractivePieChart'));
const TenetLogo = lazy(() => import('./components/TenetLogo'));
const TerminalPanel = lazy(() => import('./components/TerminalPanel'));
const UnifiedArchitectureSection = lazy(() => import('./components/UnifiedArchitectureSection'));

function App() {
  return (
    <>
      {/* Navbar stays outside Suspense for fast first paint */}
      <Navbar />
      
      <Suspense fallback={<div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '50vh' }}>Loading...</div>}>
        <Hero />
        <FeaturesSection />
        <StatsSection />
        <CtaSection />
        <BreachCards />
        <ComparisonTable />
        <DemoSection />
        <Footer />
        <InstallSection />
        <InteractivePieChart />
        <TenetLogo />
        <TerminalPanel />
        <UnifiedArchitectureSection />
      </Suspense>
    </>
  );
}
export default App;