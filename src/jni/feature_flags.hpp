#ifndef FEATURE_FLAGS_HPP
#define FEATURE_FLAGS_HPP

/**
 * Prints memory mappings, `fd`s and
 * technical details of Bipan once injected into
 * the app's process.
 * 
 * Shouldn't log too much.
 */
// #define IN_APP_DEBUG_LOGGING


/**
 * Features or refactors that are interesting
 * or help me with debugging. Some stuff might be shipped
 * out of this FT to become an actual feature!
 */
#define IN_APP_DEV_EXPERIMENTS

/**
 * Logs time taken to acquire a lock for the IPC shared memory region 
 * and Broker round-trip (IPC) time.
 * 
 * This is will log a lot.
 */
// #define IN_APP_PERF_ANALYSIS

/**
 * WIP: installs handlers for
 * useful signals in the injected side
 */
// #define IN_APP_ADDITIONAL_HANDLERS

/**
 * For some reason, some apps crash if this off.
 * 
 * If enabled, the SIGSYS handler registration is done in assembly,
 * bypassing `bionic`'s wrappers and `libsigchain.so`, registering
 * our handler directly with the kernel.
 *
 * Otherwise, it's done through the `bionic` provided `sigaction()`.
 *
 * Still studying whether this is a good idea. Turning it off is
 * may be useful for debugging as we save the system's
 * original dispositions so `tombstoned`/`debuggerd` 
 * can generate dumps.
 */
#define IN_APP_RAW_SIGNAL_REGISTRATION

/**
 * Logs all stats/accesses/opens Broker-side.
 * This may log a lot. 
 */
// #define BROKER_DEBUG_LOGGING

/**
 * Logs the stack unwinding iterations and lib search in
 * /proc/self/maps.
 * 
 * This will log a lot.
 */
// #define BROKER_UNWINDER_LOGGING

#endif