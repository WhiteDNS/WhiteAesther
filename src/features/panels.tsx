import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";

/** One labelled control on its own row, with a rule above it. */
export function Row({
  title,
  help,
  children,
  first,
}: {
  title: string;
  help?: string;
  children: React.ReactNode;
  first?: boolean;
}) {
  return (
    <>
      {first ? null : <Separator />}
      <div className="flex items-center justify-between gap-6 py-3.5">
        <div className="flex max-w-[60%] flex-col gap-1">
          <Label className="text-[13.5px]">{title}</Label>
          {help ? <span className="text-[13px] leading-snug text-muted-foreground">{help}</span> : null}
        </div>
        <div className="shrink-0">{children}</div>
      </div>
    </>
  );
}

export function Seg<T extends string>({
  value,
  options,
  onChange,
}: {
  value: T;
  options: Array<[T, string]>;
  onChange: (value: T) => void;
}) {
  return (
    <Tabs value={value} onValueChange={(next) => onChange(next as T)}>
      <TabsList className="h-9">
        {options.map(([id, label]) => (
          <TabsTrigger key={id} value={id} className="px-3 py-1 text-[13px]">
            {label}
          </TabsTrigger>
        ))}
      </TabsList>
    </Tabs>
  );
}

export function TextField({
  label,
  value,
  onChange,
  placeholder,
  type = "text",
  mono,
  help,
  error,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  type?: string;
  mono?: boolean;
  help?: string;
  error?: string | null;
}) {
  return (
    <div className="flex flex-col gap-2">
      <Label className="text-[13.5px]">{label}</Label>
      <Input
        type={type}
        className={mono ? "font-mono" : undefined}
        value={value}
        placeholder={placeholder}
        onChange={(event) => onChange(event.target.value)}
      />
      {error ? (
        <span className="text-[13px] leading-snug text-destructive">{error}</span>
      ) : help ? (
        <span className="text-[13px] leading-snug text-muted-foreground">{help}</span>
      ) : null}
    </div>
  );
}

/** A number bounded by what the backend will accept, so the value cannot be saved into a rejection. */
export function NumberField({
  label,
  value,
  onChange,
  min,
  max,
  unit,
  help,
}: {
  label?: string;
  value: number;
  onChange: (value: number) => void;
  min: number;
  max: number;
  unit?: string;
  help?: string;
}) {
  return (
    <div className="flex flex-col gap-2">
      {label ? <Label className="text-[13.5px]">{label}</Label> : null}
      <div className="relative">
        <Input
          type="number"
          min={min}
          max={max}
          className="tabular pe-12 font-mono"
          value={value}
          onChange={(event) => {
            const next = Number(event.target.value);
            if (Number.isFinite(next)) onChange(Math.min(max, Math.max(min, next)));
          }}
        />
        {unit ? (
          <span className="pointer-events-none absolute end-3 top-1/2 -translate-y-1/2 text-xs text-muted-foreground">
            {unit}
          </span>
        ) : null}
      </div>
      {help ? <span className="text-[13px] leading-snug text-muted-foreground">{help}</span> : null}
    </div>
  );
}

export function RulesField({
  label,
  value,
  onChange,
  placeholder,
  help,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  help?: string;
}) {
  return (
    <div className="flex flex-col gap-2">
      <Label className="text-[13.5px]">{label}</Label>
      <Textarea
        rows={5}
        className="font-mono text-[12.5px]"
        value={value}
        placeholder={placeholder}
        onChange={(event) => onChange(event.target.value)}
      />
      {help ? <span className="text-[13px] leading-snug text-muted-foreground">{help}</span> : null}
    </div>
  );
}
