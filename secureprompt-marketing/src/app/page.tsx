import { SideNav } from "@/components/SideNav";
import { Marquee } from "@/components/Marquee";
import { EditorialObserver } from "@/components/EditorialObserver";
import { Hero } from "@/components/sections/Hero";
import { Problem } from "@/components/sections/Problem";
import { RevealShow } from "@/components/sections/RevealShow";
import { Platform } from "@/components/sections/Platform";
import { PullQuote } from "@/components/sections/PullQuote";
import { Mechanics } from "@/components/sections/Mechanics";
import { AuditDemo } from "@/components/sections/AuditDemo";
import { OnPrem } from "@/components/sections/OnPrem";
import { Audience } from "@/components/sections/Audience";
import { FinalCTA } from "@/components/sections/FinalCTA";
import { Footer } from "@/components/Footer";

export default function HomePage() {
  return (
    <>
      <SideNav />
      <Marquee />
      <Hero />
      <Problem />
      <RevealShow />
      <Platform />
      <PullQuote />
      <Mechanics />
      <AuditDemo />
      <OnPrem />
      <Audience />
      <FinalCTA />
      <Footer />
      <EditorialObserver />
    </>
  );
}
