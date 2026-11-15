import { renderElmApp } from './elmHarness';
import { serverData } from './serverData';

export default {
  title: 'Onboarding/Form',
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

export const MinimalReady = {
  args: {
    serverData: { ...serverData, showAdvancedOptions: false },
    localData: { orderPhysicalCard: false },
  },
};

export const MinimalEmailVerified = {
  args: {
    serverData: { ...serverData, showAdvancedOptions: false, emailVerified: true },
    localData: { orderPhysicalCard: false },
  },
};

export const BasicModeReady = {};

export const BasicModeEmailVerified = {
  args: {
    serverData: { ...serverData, emailVerified: true },
  },
};

export const AdvancedModeReady = {
  args: {
    serverData: { ...serverData, showAdvancedOptions: true },
  },
};

export const AdvancedModeEmailVerified = {
  args: {
    serverData: { ...serverData, showAdvancedOptions: true, emailVerified: true },
  },
};