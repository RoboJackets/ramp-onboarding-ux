import { renderElmApp } from './elmHarness';
import { serverData } from './serverData';

export default {
  title: 'Onboarding Form/Minimal',
  render: (args) => renderElmApp({
    serverData: args.serverData,
    localData: JSON.stringify(args.localData),
    storybookState: args.storybookState,
  }),
  args: {
    serverData,
    localData: { orderPhysicalCard: true },
  },
};

export const Ready = {
  args: {
    serverData: { ...serverData, showAdvancedOptions: false },
    localData: { orderPhysicalCard: false },
  },
};

export const EmailVerified = {
  args: {
    serverData: { ...serverData, showAdvancedOptions: false, emailVerified: true },
    localData: { orderPhysicalCard: false },
  },
};