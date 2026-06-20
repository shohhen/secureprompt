import { SideNav } from "@/components/SideNav";
import { Marquee } from "@/components/Marquee";
import { EditorialObserver } from "@/components/EditorialObserver";
import { Hero } from "@/components/sections/Hero";
import { Leak } from "@/components/sections/Leak";
import { Gateway } from "@/components/sections/Gateway";
import { Inside } from "@/components/sections/Inside";
import { Proof } from "@/components/sections/Proof";
import { OnPrem } from "@/components/sections/OnPrem";
import { FinalCTA } from "@/components/sections/FinalCTA";
import { Footer } from "@/components/Footer";

export default function HomePage() {
  return (
    <>
      <SideNav />
      <Marquee />
      <Hero />
      <Leak />
      <Gateway />
      <Inside />
      <Proof />
      <OnPrem />
      <FinalCTA />
      <Footer />
      <EditorialObserver />
    </>
  );
}
